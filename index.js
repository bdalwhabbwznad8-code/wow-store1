// ═══════════════════════════════════════════════════════════════
// WOW STORE — Cloudflare Worker — v12.0
// KV Binding : env.DATABASE
// ═══════════════════════════════════════════════════════════════

// ── تشفير كلمة المرور ──
async function hashPass(str){
  const buf=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}

const ADMIN_PASS_HASH = "881b9563ffff9349eb3ad4efeb71c7355d7878644e385d71d26b846f3ddd06a6";
const BLOCK_MS = 8*3600000;
const MAX_ATT  = 5;

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
async function kvGetFresh(env,key,def=null){
  try{const v=await env.DATABASE.get(key);return v?JSON.parse(v):def;}catch{return def;}
}
async function kvSet(env,key,val,opts={}){try{await env.DATABASE.put(key,JSON.stringify(val),opts);}catch(e){console.error("KV set error:",key,e);}}

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
    if(!sub.endpoint.startsWith("https://"))return;
    await fetch(sub.endpoint,{method:"POST",headers:{"Content-Type":"application/json","TTL":"86400"},body:JSON.stringify({title,body})}).catch(()=>{});
  }catch{}
}

// ── م35: سجل العمليات المركزي غير القابل للتعديل ──
async function logActivity(env,type,details,actor="system"){
  try{
    const log=await kvGet(env,"activity_log",[]);
    log.unshift({
      t:new Date().toISOString(),
      type,
      details,
      actor,           // هوية المنفذ
      immutable:true   // علامة عدم التعديل
    });
    await kvSet(env,"activity_log",log.slice(0,1000)); // رفع الحد لـ 1000 سجل
  }catch{}
}

// ── م2: تصنيف الأجهزة حسب القدرة الشرائية ──
function parseUserAgent(ua){
  if(!ua)return{device:"Unknown",brand:"Unknown",model:"Unknown",tier:"mid",os:"Unknown",browser:"Unknown"};
  let device="Desktop",brand="Desktop",model="Desktop",tier="mid",os="Unknown",browser="Unknown";
  if(/Edg\//.test(ua))browser="Edge";
  else if(/OPR\/|Opera/.test(ua))browser="Opera";
  else if(/Chrome\//.test(ua))browser="Chrome";
  else if(/Firefox\//.test(ua))browser="Firefox";
  else if(/Safari\//.test(ua)&&!/Chrome/.test(ua))browser="Safari";
  if(/Windows NT/.test(ua)){os="Windows";brand="Desktop";model="Windows PC";device="Desktop";tier="mid";}
  else if(/Macintosh|Mac OS X/.test(ua)&&!/iPhone|iPad/.test(ua)){os="macOS";brand="Desktop";model="Mac";device="Desktop";tier="flagship";}
  else if(/Linux/.test(ua)&&!/Android/.test(ua)){os="Linux";brand="Desktop";model="Linux PC";device="Desktop";tier="mid";}
  else if(/iPhone/.test(ua)){
    os="iOS";brand="Apple";device="iPhone";
    const m=ua.match(/iPhone OS ([\d_]+)/);const ver=m?parseFloat(m[1].replace(/_/g,".")):0;
    if(ver>=18){model="iPhone 16 Series";tier="flagship";}
    else if(ver>=17){model="iPhone 15 Series";tier="flagship";}
    else if(ver>=16){model="iPhone 14 Series";tier="flagship";}
    else if(ver>=15){model="iPhone 13 Series";tier="flagship";}
    else if(ver>=14){model="iPhone 12 Series";tier="mid";}
    else if(ver>=13){model="iPhone 11 Series";tier="mid";}
    else{model="iPhone (legacy)";tier="budget";}
  }else if(/iPad/.test(ua)){os="iPadOS";brand="Apple";device="iPad";model="iPad";tier="mid";}
  else if(/Android/.test(ua)){
    os="Android";const bm=ua.match(/;\s*([^;()]+?)\s+Build\//);const rawModel=bm?bm[1].trim():"Android";
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

// ── م6: توليد باركود SVG Code128 بدون مكتبات ──
function encodeCode128(text){
  const BARS=["11011001100","11001101100","11001100110","10010011000","10010001100","10001001100","10011001000","10011000100","10001100100","11001001000","11001000100","11000100100","10110011100","10011011100","10011001110","10111001100","10011101100","10011100110","11001110010","11001011100","11001001110","11011100100","11001110100","11101101110","11101001100","11100101100","11100100110","11101100100","11100110100","11100110010","11011011000","11011000110","11000110110","10100011000","10001011000","10001000110","10110001000","10001101000","10001100010","11010001000","11000101000","11000100010","10110111000","10110001110","10001101110","10111011000","10111000110","10001110110","11101110110","11010001110","11000101110","11011101000","11011100010","11101011000","11101000110","11100010110","11101101000","11101100010","11100011010","11101111010","11001000010","11110001010","10100110000","10100001100","10010110000","10010000110","10000101100","10000100110","10110010000","10110000100","10011010000","10011000010","10000110100","10000110010","11000010010","11001010000","11110111010","11000010100","10001111010","10100111100","10010111100","11110100010","11110010010","11011111010","11111011010","11001111010","10100011110","10001011110","10010001111","10000101111","11011110100","11011110010","11110100100","11110010100","11110101000","11110101100","11100111010","11110111100","11010111100","11110101110","11011010000","11011010110"];
  const BVALS={" ":0,"!":1,'"':2,"#":3,"$":4,"%":5,"&":6,"'":7,"(":8,")":9,"*":10,"+":11,",":12,"-":13,".":14,"/":15,"0":16,"1":17,"2":18,"3":19,"4":20,"5":21,"6":22,"7":23,"8":24,"9":25,":":26,";":27,"<":28,"=":29,">":30,"?":31,"@":32,"A":33,"B":34,"C":35,"D":36,"E":37,"F":38,"G":39,"H":40,"I":41,"J":42,"K":43,"L":44,"M":45,"N":46,"O":47,"P":48,"Q":49,"R":50,"S":51,"T":52,"U":53,"V":54,"W":55,"X":56,"Y":57,"Z":58,"[":59,"\\":60,"]":61,"^":62,"_":63,"`":64,"a":65,"b":66,"c":67,"d":68,"e":69,"f":70,"g":71,"h":72,"i":73,"j":74,"k":75,"l":76,"m":77,"n":78,"o":79,"p":80,"q":81,"r":82,"s":83,"t":84,"u":85,"v":86,"w":87,"x":88,"y":89,"z":90};
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

// ── م1: فاتورة متقدمة — تتبع وقت وحالة الطباعة ──
function buildInvoiceHTML(o,s,opts={}){
  const hideShipping=opts.hideShipping||false;
  const extraNote=_escSrv(opts.extraNote||"");
  const sn=_escSrv(s.storeName||"WOW STORE"),wa=_escSrv(s.whatsapp||"");
  const ST={processing:"قيد المعالجة",shipped:"تم الشحن",delivered:"تم التوصيل",returned:"مرتجعة"};
  const SC={processing:"#f59e0b",shipped:"#3b82f6",delivered:"#22c55e",returned:"#ef4444"};
  const stTxt=ST[o.status]||o.status||"";const stC=SC[o.status]||"#a855f7";
  const printTs=new Date().toISOString();
  const iH=(o.items||[]).map(it=>`<tr>
    <td style="padding:6px;border-bottom:1px solid #eee">${it.img?`<img src="${_escSrv(it.img)}" style="width:42px;height:52px;object-fit:cover;border-radius:4px">`:""}</td>
    <td style="padding:6px;border-bottom:1px solid #eee;font-size:12px">${_escSrv(it.name||"")}${it.size?` <small style="color:#888">[${_escSrv(it.size)}]</small>`:""}</td>
    <td style="padding:6px;border-bottom:1px solid #eee;text-align:center;font-size:12px">${it.qty||1}</td>
    <td style="padding:6px;border-bottom:1px solid #eee;font-size:12px;white-space:nowrap">${((it.price||0)*(it.qty||1)).toLocaleString()} دج</td>
  </tr>`).join("");
  return `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>فاتورة ${_escSrv(o.id)}</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f5f5;padding:16px;color:#111}.wrap{max-width:580px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.1)}.hdr{background:#0a0016;color:#fff;padding:22px;text-align:center}.brand{font-family:Georgia,serif;font-size:34px;font-weight:900;letter-spacing:6px;color:#c084fc}.sub{font-size:10px;color:rgba(255,255,255,.4);letter-spacing:3px;margin-top:2px}.oid{font-size:12px;color:rgba(255,255,255,.5);margin-top:10px}.dt{font-size:11px;color:rgba(255,255,255,.3)}.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;margin-top:8px;background:${stC}22;color:${stC}}.body{padding:18px}.row{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px}.col{flex:1;min-width:160px;background:#fafafa;border-radius:8px;padding:12px}.col h4{font-size:9px;color:#888;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;border-bottom:1px solid #eee;padding-bottom:4px}.col p{font-size:11px;color:#444;line-height:1.9}table{width:100%;border-collapse:collapse;margin-bottom:14px}thead th{padding:7px 6px;font-size:9px;color:#888;letter-spacing:1px;text-transform:uppercase;text-align:right;background:#fafafa}thead th:last-child{text-align:left}.totbox{background:#fafafa;border-radius:8px;padding:12px 14px}.tr{display:flex;justify-content:space-between;font-size:12px;color:#555;padding:2px 0}.tr.final{font-size:15px;font-weight:700;color:#111;border-top:2px solid #e0e0e0;margin-top:6px;padding-top:8px}.no-print{text-align:center;margin-bottom:14px;display:flex;gap:6px;justify-content:center;flex-wrap:wrap}.ft{text-align:center;padding:14px;color:#aaa;font-size:10px;border-top:1px solid #eee}.print-ts{font-size:9px;color:#bbb;text-align:center;padding:4px;direction:ltr}@media print{.no-print{display:none}body{background:#fff;padding:0}.wrap{box-shadow:none;border-radius:0}}</style>
<script>
// م1: تتبع حالة الطباعة لمنع تكرار الطلبات
window.addEventListener('beforeprint',function(){
  var k='printed_'+${JSON.stringify(o.id)};
  var prev=localStorage.getItem(k);
  if(prev){
    var c=document.getElementById('print-warn');
    if(c){c.style.display='block';c.textContent='تحذير: تمت طباعة هذه الفاتورة مسبقاً في '+prev;}
  }
  localStorage.setItem(k,new Date().toLocaleString('ar-DZ'));
});
function savePDF(){window.print();}
</script>
</head>
<body>
<div class="no-print">
  <button onclick="window.print()" style="background:#6d28d9;color:#fff;border:none;border-radius:7px;padding:8px 18px;font-size:12px;cursor:pointer">طباعة / PDF</button>
  <button onclick="window.close()" style="background:#eee;color:#333;border:none;border-radius:7px;padding:8px 18px;font-size:12px;cursor:pointer">اغلاق</button>
</div>
<div id="print-warn" style="display:none;background:#fef3c7;border:1px solid #f59e0b;border-radius:6px;padding:8px;font-size:11px;color:#92400e;margin-bottom:10px;text-align:center"></div>
<div class="wrap">
<div class="hdr"><div class="brand">${sn}</div><div class="sub">INVOICE</div><div class="oid">${_escSrv(o.id)}</div><div class="dt">${new Date(o.date).toLocaleString("ar-DZ")}</div><div class="badge">${stTxt}</div></div>
<div class="body">
<div class="row">
<div class="col"><h4>بيانات العميل</h4><p><strong>${_escSrv(o.name||"")}</strong></p><p>${_escSrv(o.phone1||"")} / ${_escSrv(o.phone2||"")}</p>${o.email?`<p>${_escSrv(o.email)}</p>`:""}</div>
${!hideShipping?`<div class="col"><h4>التوصيل</h4><p>${_escSrv(o.wilaya||"")} / ${_escSrv(o.commune||"")}</p><p>${_escSrv(o.dlbl||"Stop Desk")}</p><p>${o.payMethod==="ccp"?"CCP مسبق":"الدفع عند الاستلام"}</p>${o.confirmed?`<p style="color:#22c55e">مؤكدة</p>`:`<p style="color:#f59e0b">بانتظار التأكيد</p>`}</div>`:""}
</div>
<table><thead><tr><th>صورة</th><th>المنتج</th><th style="text-align:center">الكمية</th><th style="text-align:left">المبلغ</th></tr></thead><tbody>${iH}</tbody></table>
<div class="totbox">
<div class="tr"><span>المنتجات</span><span>${(o.originalSub||o.finalSub||0).toLocaleString()} دج</span></div>
${o.discAmt>0?`<div class="tr" style="color:#22c55e"><span>خصم العرض</span><span>- ${o.discAmt.toLocaleString()} دج</span></div>`:""}
${o.couponCode?`<div class="tr" style="color:#22c55e"><span>كوبون (${_escSrv(o.couponCode)})</span><span>- ${(o.couponDisc||0).toLocaleString()} دج</span></div>`:""}
${!hideShipping?`<div class="tr"><span>رسوم التوصيل</span><span>${(o.fee||0).toLocaleString()} دج</span></div>`:""}
${o.ccpDisc>0?`<div class="tr" style="color:#22c55e"><span>خصم CCP</span><span>- ${o.ccpDisc} دج</span></div>`:""}
<div class="tr final"><span>المجموع الكلي</span><span>${(o.total||0).toLocaleString()} دج</span></div>
</div>
${o.note?`<div style="margin-top:12px;background:#fff9e6;border:1px solid #fcd34d;border-radius:6px;padding:9px 11px;font-size:11px;color:#92400e"><strong>ملاحظة:</strong> ${_escSrv(o.note)}</div>`:""}
${extraNote?`<div style="margin-top:8px;background:#f0f9ff;border:1px solid #bae6fd;border-radius:6px;padding:9px 11px;font-size:11px;color:#0369a1"><strong>ملاحظة اضافية:</strong> ${extraNote}</div>`:""}
</div>
<div class="ft">${sn} &middot; ${wa}</div>
</div>
<div class="print-ts" dir="ltr">Generated: ${printTs}</div>
</body></html>`;
}

// ── م6: بوليصة شحن متقدمة ──
function buildShippingLabel(o,s,fmt){
  const sn=_escSrv(s.storeName||"WOW STORE"),wa=_escSrv(s.whatsapp||"");
  const fmtN={yalidine:"Yalidine",zr:"Zr Express",maystro:"Maystro"}[fmt]||"Yalidine";
  const iL=(o.items||[]).map(it=>`${it.name||""}${it.size?" ["+it.size+"]":""} x${it.qty||1}`).join("، ");
  const bc=encodeCode128(o.id||"WOW");
  return `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>بوليصة ${_escSrv(o.id)}</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#fff;color:#111;padding:14px}.label{width:148mm;min-height:105mm;border:2px solid #222;border-radius:6px;padding:12px}.hdr{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #222;padding-bottom:8px;margin-bottom:8px}.brand{font-family:Georgia,serif;font-size:20px;font-weight:900;letter-spacing:4px}.fmt-tag{background:#222;color:#fff;font-size:9px;padding:2px 7px;border-radius:3px;letter-spacing:1px}.bc{text-align:center;margin:6px 0;overflow:hidden}.row{display:flex;gap:10px;margin-bottom:8px}.box{flex:1;border:1px solid #ddd;border-radius:4px;padding:8px}.box h4{font-size:8px;color:#888;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;border-bottom:1px solid #eee;padding-bottom:3px}.box p{font-size:11px;line-height:1.8}.items{background:#f9f9f9;border-radius:4px;padding:7px;font-size:10px;color:#555;margin-bottom:8px}.amt{background:#f0f0f0;border-radius:4px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}.amt span{font-size:10px;color:#555}.amt strong{font-size:18px;font-weight:900}.prepaid{background:#111;color:#fff;text-align:center;padding:7px;border-radius:4px;font-size:13px;font-weight:700;letter-spacing:2px;margin-bottom:8px}.notes{border:1px dashed #ccc;border-radius:4px;padding:8px;min-height:28px;font-size:10px;color:#bbb}.no-print{text-align:center;margin-bottom:12px;display:flex;gap:6px;justify-content:center}@media print{.no-print{display:none}body{padding:0}}</style></head>
<body>
<div class="no-print">
  <button onclick="window.print()" style="background:#111;color:#fff;border:none;border-radius:6px;padding:8px 16px;cursor:pointer;font-size:12px">طباعة</button>
  <select onchange="window.location.href='/shipping-label?id=${_escSrv(o.id)}&fmt='+this.value" style="border:1px solid #ccc;border-radius:6px;padding:7px;font-size:11px;cursor:pointer">
    <option value="yalidine"${fmt==="yalidine"?" selected":""}>Yalidine</option>
    <option value="zr"${fmt==="zr"?" selected":""}>Zr Express</option>
    <option value="maystro"${fmt==="maystro"?" selected":""}>Maystro</option>
  </select>
</div>
<div class="label">
<div class="hdr"><div><div class="brand">${sn}</div><div style="font-size:10px;color:#555;margin-top:2px">${wa}</div></div><div style="text-align:left"><div class="fmt-tag">${fmtN}</div><div style="font-size:11px;font-weight:700;margin-top:4px">${_escSrv(o.id)}</div><div style="font-size:9px;color:#777">${new Date(o.date).toLocaleDateString("ar-DZ")}</div></div></div>
<div class="bc">${bc}</div>
<div class="row">
<div class="box"><h4>المرسل</h4><p><strong>${sn}</strong></p><p>${wa}</p></div>
<div class="box"><h4>المستلم</h4><p><strong>${_escSrv(o.name||"")}</strong></p><p>${_escSrv(o.phone1||"")} / ${_escSrv(o.phone2||"")}</p><p>${_escSrv(o.wilaya||"")} — ${_escSrv(o.commune||"")}</p><p style="font-size:9px;color:#777">${_escSrv(o.dlbl||"Stop Desk")}</p></div>
</div>
<div class="items">${_escSrv(iL)}</div>
${o.payMethod!=="ccp"?`<div class="amt"><span>مبلغ التحصيل</span><strong>${(o.total||0).toLocaleString()} دج</strong></div>`:`<div class="prepaid">مدفوع مسبقا CCP</div>`}
<div class="notes">ملاحظات: _________________</div>
</div></body></html>`;
}

// ── م13: بناء مستند طباعة جماعية للفواتير ──
function buildBulkPrintHTML(orders,settings){
  const sn=_escSrv(settings.storeName||"WOW STORE");
  const pages=orders.map(o=>buildInvoiceHTML(o,settings)).join('<div style="page-break-after:always"></div>');
  return `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>طباعة جماعية — ${sn}</title>
<style>@media print{.no-print{display:none}.page-break{page-break-after:always}}body{font-family:-apple-system,sans-serif;background:#f5f5f5}
.no-print{text-align:center;padding:14px;background:#fff;border-bottom:1px solid #ddd;position:sticky;top:0;z-index:10;display:flex;gap:8px;justify-content:center;align-items:center}
</style></head><body>
<div class="no-print">
  <strong style="font-size:13px">${orders.length} فاتورة</strong>
  <button onclick="window.print()" style="background:#6d28d9;color:#fff;border:none;border-radius:7px;padding:8px 20px;font-size:13px;cursor:pointer">طباعة الكل</button>
  <button onclick="window.close()" style="background:#eee;color:#333;border:none;border-radius:7px;padding:8px 16px;font-size:12px;cursor:pointer">اغلاق</button>
</div>
${pages}</body></html>`;
}

export default {
  async fetch(request,env){
    try{
    const url=new URL(request.url);
    const path=url.pathname;
    const method=request.method;
    const RR=(body,status=200,extra={})=>R(body,status,extra,request);
    if(method==="OPTIONS")return new Response(null,{headers:_getCorsHeaders(request)});

    // ── Service Worker ──
    if(path==="/sw.js"&&method==="GET")return RR(`self.addEventListener("push",function(e){var d={title:"WOW Store",body:""};try{d=e.data?e.data.json():d;}catch(_){}e.waitUntil(self.registration.showNotification(d.title||"WOW Store",{body:d.body||""}));});self.addEventListener("notificationclick",function(e){e.notification.close();e.waitUntil(clients.openWindow("/"));});`,200,{"Content-Type":"application/javascript;charset=utf-8","Cache-Control":"public,max-age=3600"});

    // ── المصادقة ──
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
        await logActivity(env,"admin_login","تسجيل دخول ناجح","admin");
        return RR({ok:true,token});
      }
      const after=await incRL(env,fp);
      await sendPush(env,"محاولة دخول خاطئة","محاولة "+(MAX_ATT-(after.remaining||0))+" من "+MAX_ATT);
      await logActivity(env,"admin_login_fail","محاولة دخول فاشلة من "+getFP(request));
      if(after.blocked)return RR({ok:false,stall:true});
      return RR({ok:false,remaining:after.remaining},401);
    }

    if(path==="/api/auth-verify"&&method==="POST")return RR({ok:await isAdmin(request,env)});

    if(path==="/api/logout"&&method==="POST"){
      const k=request.headers.get("X-Admin-Key")||"";
      if(k){try{await env.DATABASE.delete("admin_token:"+k);}catch{}}
      await logActivity(env,"admin_logout","تسجيل خروج");
      return RR({ok:true});
    }

    if(path==="/api/push-subscribe"&&method==="POST"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      await kvSet(env,"push_subscription",await request.json());
      return RR({ok:true});
    }

    // ── م28: المنتجات مع فلتر showAt والجدولة ──
    if(path==="/api/products"){
      if(method==="GET"){
        const [prods,flashSales]=await Promise.all([kvGet(env,"products",[]),kvGet(env,"flash_sales",[])]);
        const now=Date.now();
        const activeFlash=flashSales.filter(f=>f.active&&new Date(f.startAt).getTime()<=now&&new Date(f.endAt).getTime()>now);
        // م28: حجب المنتجات التي لم يحن وقت نشرها
        const visibleProds=prods.filter(p=>!p.archived&&(!p.showAt||new Date(p.showAt).getTime()<=now));
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
        // م26: دعم المتغيرات المتقدمة (حجم + لون + كمية مستقلة)
        const _variants=Array.isArray(body.variants)?body.variants.slice(0,50).map(v=>({
          size:(v.size||"").substring(0,20),
          color:(v.color||"").substring(0,30),
          qty:Math.max(0,parseInt(v.qty)||0),
          sku:(v.sku||"").substring(0,30)
        })):[];
        const p={
          id:Date.now(),
          name:(body.name||"").substring(0,120),
          nameEn:(body.nameEn||"").substring(0,120),
          nameFr:(body.nameFr||"").substring(0,120),
          price:Math.max(0,isNaN(_rp)?0:Math.round(_rp)),
          discount:Math.min(90,Math.max(0,isNaN(_rd)?0:Math.round(_rd))),
          costPrice:Math.max(0,parseInt(body.costPrice)||0), // م37: سعر التكلفة
          cat:VALID_CATS.includes(body.cat)?body.cat:"other",
          desc:(body.desc||"").substring(0,600),
          descEn:(body.descEn||"").substring(0,600),
          descFr:(body.descFr||"").substring(0,600),
          images:_safeImgs,
          stock:body.stock!==false,
          quantity:_rq!==null?(Math.max(0,Math.floor(isNaN(_rq)?0:_rq))):null,
          sizes:Array.isArray(body.sizes)?body.sizes.slice(0,20).map(s=>(s||"").substring(0,20)):[],
          colors:Array.isArray(body.colors)?body.colors.slice(0,20).map(c=>(c||"").substring(0,30)):[],
          variants:_variants, // م26
          alertQty:Math.max(0,parseInt(body.alertQty)||5), // م27: قيمة افتراضية 5
          showAt:body.showAt?new Date(body.showAt).toISOString():null, // م28
          salesCount:0,
          visits:0, // م32: تتبع زيارات المنتج
          cartAdds:0, // م32: إضافة للسلة
          createdAt:Date.now(),
          archived:false
        };
        prods.push(p);
        await kvSet(env,"products",prods);
        await logActivity(env,"product_create","منتج جديد: "+p.name);
        return RR(p);
      }
      if(method==="PUT"){
        const body=await request.json(),prods=await kvGet(env,"products",[]);
        const i=prods.findIndex(p=>p.id===body.id);
        if(i<0)return RR({error:"Not found"},404);
        const _allowed=["name","nameEn","nameFr","price","discount","costPrice","desc","descEn","descFr","images","stock","quantity","cat","sizes","colors","variants","alertQty","showAt","archived"];
        const _upd={};
        _allowed.forEach(f=>{if(body[f]!==undefined)_upd[f]=body[f];});
        if(_upd.price!==undefined)_upd.price=Math.max(0,isNaN(+_upd.price)?0:Math.round(+_upd.price));
        if(_upd.discount!==undefined)_upd.discount=Math.min(90,Math.max(0,isNaN(+_upd.discount)?0:Math.round(+_upd.discount)));
        if(_upd.quantity!==undefined&&_upd.quantity!==null){
          _upd.quantity=Math.max(0,Math.floor(isNaN(+_upd.quantity)?0:+_upd.quantity));
          // م27: تنبيه مخزون منخفض
          const alertQty=prods[i].alertQty||5;
          if(_upd.quantity<=alertQty&&_upd.quantity<(prods[i].quantity||999)){
            await sendPush(env,"مخزون منخفض",prods[i].name+" — متبقي: "+_upd.quantity+" قطعة");
            await logActivity(env,"stock_alert","مخزون منخفض: "+prods[i].name+" ("+_upd.quantity+")");
          }
        }
        if(_upd.images!==undefined)_upd.images=Array.isArray(_upd.images)?_upd.images.slice(0,4).filter(u=>typeof u==="string"&&u.length<500000).map(u=>u.trim()):[];
        const VALID_CATS2=["shirts","pants","shorts","hats","accessories","other"];
        if(_upd.cat!==undefined&&!VALID_CATS2.includes(_upd.cat))_upd.cat="other";
        // م12: سجل التعديل
        const auditEntry={t:new Date().toISOString(),type:"product_update",fields:Object.keys(_upd)};
        const auditTrail=prods[i].auditTrail||[];
        auditTrail.unshift(auditEntry);
        _upd.auditTrail=auditTrail.slice(0,20);
        prods[i]={...prods[i],..._upd};
        await kvSet(env,"products",prods);
        await logActivity(env,"product_update","تعديل: "+prods[i].name+" ("+Object.keys(_upd).join(",")+")");
        return RR(prods[i]);
      }
      if(method==="DELETE"){
        const id=+url.searchParams.get("id");
        const archive=url.searchParams.get("archive")==="1";
        let prods=await kvGet(env,"products",[]);
        const pi=prods.findIndex(p=>p.id===id);
        if(pi<0)return RR({error:"Not found"},404);
        if(archive){
          // م4: الأرشفة — سحب المنتج من الواجهة مع الاحتفاظ ببياناته
          const arch=await kvGet(env,"archived_products",[]);
          const p=prods.splice(pi,1)[0];
          p.archivedAt=new Date().toISOString();
          p.archived=true;
          arch.unshift(p);
          await Promise.all([kvSet(env,"products",prods),kvSet(env,"archived_products",arch)]);
          await logActivity(env,"product_archive","أرشفة: "+p.name);
        } else {
          const pName=prods[pi].name||"";
          prods.splice(pi,1);
          await kvSet(env,"products",prods);
          await logActivity(env,"product_delete","حذف نهائي: "+pName);
        }
        return RR({ok:true});
      }
    }

    // ── م32: تتبع زيارات/سلة المنتجات ──
    if(path==="/api/products/track"&&method==="POST"){
      const{id,event}=await request.json().catch(()=>({}));
      if(!id||!["view","cart","purchase"].includes(event))return RR({ok:false});
      const prods=await kvGet(env,"products",[]);
      const pi=prods.findIndex(p=>String(p.id)===String(id));
      if(pi<0)return RR({ok:false});
      if(event==="view")prods[pi].visits=(prods[pi].visits||0)+1;
      else if(event==="cart")prods[pi].cartAdds=(prods[pi].cartAdds||0)+1;
      else if(event==="purchase")prods[pi].salesCount=(prods[pi].salesCount||0)+1;
      await kvSet(env,"products",prods);
      return RR({ok:true});
    }

    // ── م4: الأرشيف — فلترة وإدارة ──
    if(path==="/api/products/archive"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="GET"){
        const cat=url.searchParams.get("cat");
        let arch=await kvGet(env,"archived_products",[]);
        if(cat)arch=arch.filter(p=>p.cat===cat);
        return RR(arch);
      }
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        const{action,id,ids}=b;
        if(action==="restore"){
          // استعادة منتج واحد
          const arch=await kvGet(env,"archived_products",[]);
          const ai=arch.findIndex(p=>p.id===id||p.id===+id);
          if(ai<0)return RR({error:"Not found"},404);
          const p=arch.splice(ai,1)[0];
          delete p.archivedAt;p.archived=false;
          const prods=await kvGet(env,"products",[]);prods.unshift(p);
          await Promise.all([kvSet(env,"products",prods),kvSet(env,"archived_products",arch)]);
          await logActivity(env,"product_restore","استعادة: "+p.name);
          return RR({ok:true});
        }
        if(action==="bulk_restore"&&Array.isArray(ids)){
          // م4: استعادة جماعية
          const arch=await kvGet(env,"archived_products",[]);
          const prods=await kvGet(env,"products",[]);
          const restored=[];
          for(const rid of ids.slice(0,50)){
            const ai=arch.findIndex(p=>String(p.id)===String(rid));
            if(ai>=0){
              const p=arch.splice(ai,1)[0];
              delete p.archivedAt;p.archived=false;
              prods.unshift(p);restored.push(p.name||"");
            }
          }
          await Promise.all([kvSet(env,"products",prods),kvSet(env,"archived_products",arch)]);
          await logActivity(env,"product_bulk_restore","استعادة جماعية: "+restored.length+" منتج");
          return RR({ok:true,count:restored.length});
        }
        return RR({error:"Invalid action"},400);
      }
    }

    // ── الطلبيات ──
    if(path==="/api/orders"){
      if(method==="POST"){
        const orderFp="ofp:"+getFP(request);
        const orderRl=await kvGet(env,orderFp,{c:0,t:0});
        const now=Date.now();
        if(orderRl.t&&now-orderRl.t<60000&&orderRl.c>=5)
          return RR({error:"الرجاء الانتظار قبل إرسال طلبية أخرى"},429);

        const body=await request.json();
        if(!body.name||!body.phone1||!body.phone2||!body.wilaya||!body.commune||!body.items?.length)
          return RR({error:"Missing fields"},400);
        if(body.phone1===body.phone2)return RR({error:"Phones must differ"},400);
        const phoneRx=/^0[567]\d{8}$/;
        if(!phoneRx.test(body.phone1.replace(/\s/g,""))||!phoneRx.test(body.phone2.replace(/\s/g,"")))
          return RR({error:"رقم الهاتف غير صالح"},400);
        if(body.items.length>20)return RR({error:"عدد المنتجات كبير جداً"},400);

        const newC=now-orderRl.t>60000?1:(orderRl.c||0)+1;
        await env.DATABASE.put(orderFp,JSON.stringify({c:newC,t:now}),{expirationTtl:120});

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

        const [prodsData,settings]=await Promise.all([kvGetFresh(env,"products",[]),kvGet(env,"settings",{})]);

        for(const item of body.items){
          const itemQty=Math.max(1,Math.min(99,parseInt(item.qty)||1));
          const prod=prodsData.find(p=>p.id===item.id);
          if(!prod||prod.archived)return RR({error:"المنتج غير موجود: "+item.id},400);
          // م28: منع شراء منتج غير منشور
          if(prod.showAt&&new Date(prod.showAt).getTime()>Date.now())
            return RR({error:"هذا المنتج غير متاح بعد"},400);
          if(prod.quantity!==null&&prod.quantity!==undefined){
            if(itemQty>prod.quantity)
              return RR({error:"الكمية غير متوفرة للمنتج "+prod.name},400);
          }
        }

        let rawSubOriginal=0,subWithProductDisc=0;
        for(const item of body.items){
          const prod=prodsData.find(p=>p.id===item.id);
          const qty=Math.max(1,Math.min(99,parseInt(item.qty)||1));
          rawSubOriginal+=prod.price*qty;
          const disc=prod.discount&&prod.discount>0?Math.min(prod.discount,90):0;
          const effPrice=disc>0?Math.round(prod.price*(1-disc/100)):prod.price;
          subWithProductDisc+=effPrice*qty;
        }

        const adminDisc=Math.max(0,Math.min(90,parseInt(settings.admin_discount||0)||0));
        let appliedGlobalDisc=adminDisc,appliedDiscountMethod="global";
        const clientGD=+body.globalDiscount||0,mysteryExp=+body.mysteryExp||0;
        if(mysteryExp>Date.now()&&clientGD>=1&&clientGD<=10){appliedGlobalDisc=clientGD;appliedDiscountMethod="mystery";}
        const subWithGlobalDisc=appliedGlobalDisc>0?Math.round(rawSubOriginal*(1-appliedGlobalDisc/100)):rawSubOriginal;

        let finalSub,discountMethodFinal;
        if(subWithProductDisc<=subWithGlobalDisc){finalSub=subWithProductDisc;discountMethodFinal="product";}
        else{finalSub=subWithGlobalDisc;discountMethodFinal=appliedDiscountMethod;}
        const discAmt=rawSubOriginal-finalSub;

        const isHome=(body.dlbl||"").includes("منزل");
        const shipRow=SF[body.wilaya]||{h:1100,d:700,r:400};
        const fee=isHome?shipRow.h:shipRow.d;
        const returnFee=shipRow.r;
        const payMethod=body.payMethod||"cod";
        const ccpDisc=payMethod==="ccp"?50:0;
        const total=finalSub+fee-ccpDisc;

        const verifiedItems=body.items.map(function(item){
          const prod=prodsData.find(p=>p.id===item.id);
          const disc=prod.discount&&prod.discount>0?Math.min(prod.discount,90):0;
          const serverPrice=disc>0?Math.round(prod.price*(1-disc/100)):prod.price;
          return{id:item.id,name:(prod.name||"").substring(0,120),price:serverPrice,
            qty:Math.max(1,Math.min(99,parseInt(item.qty)||1)),
            size:(item.size||"").substring(0,10),img:(item.img||"").substring(0,500)};
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
          appliedDiscountMethod:discountMethodFinal,globalDiscount:appliedGlobalDisc,
          history:[], // م12: سجل التغييرات
          auditTrail:[] // م12: Audit Trail
        };

        // تحديث المخزون مع double-check
        const prodsRefresh=await kvGetFresh(env,"products",[]);
        let changed=false;
        for(const item of body.items){
          const pi=prodsRefresh.findIndex(p=>p.id===item.id);
          if(pi>=0&&prodsRefresh[pi].quantity!==null&&prodsRefresh[pi].quantity!==undefined){
            const needed=Math.max(1,Math.min(99,parseInt(item.qty)||1));
            if(prodsRefresh[pi].quantity<needed)
              return RR({error:"الكمية لم تعد متوفرة: "+(prodsRefresh[pi].name||item.id)},409);
            prodsRefresh[pi].quantity-=needed;changed=true;
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

        // خصم الإحالة
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

        // م5: كوبون الخصم — فحص الحد الأدنى للسلة والولاية
        let couponDisc=0,couponCode="";
        if(body.couponCode){
          const coupons=await kvGet(env,"coupons",[]);
          const ci=coupons.findIndex(x=>x.code===(body.couponCode||"").toUpperCase()&&x.active);
          if(ci>=0){
            const cp=coupons[ci];
            const expired=cp.expiresAt&&Date.now()>new Date(cp.expiresAt).getTime();
            const maxed=cp.maxUses>0&&cp.usedCount>=cp.maxUses;
            // م5: شرط الحد الأدنى للسلة
            const belowMin=cp.minSub&&finalSub<cp.minSub;
            // م5: تقييد الولاية
            const wrongWilaya=Array.isArray(cp.wilayas)&&cp.wilayas.length>0&&!cp.wilayas.includes(body.wilaya);
            if(!expired&&!maxed&&!belowMin&&!wrongWilaya){
              if(cp.discType==="percent")couponDisc=Math.round(total*(cp.discVal/100));
              else couponDisc=Math.min(cp.discVal,total);
              couponCode=cp.code;
              coupons[ci].usedCount=(coupons[ci].usedCount||0)+1;
              await kvSet(env,"coupons",coupons);
            }
          }
        }
        o.couponCode=couponCode;o.couponDisc=couponDisc;o.total=total-couponDisc;

        // م11: كشف الطلبيات المكررة (هاتف أو عنوان خلال 48 ساعة)
        const allOrders=await kvGet(env,"orders",[]);
        const cutoff48h=Date.now()-172800000;
        const prevOrder=allOrders.find(x=>{
          const isRecent=new Date(x.date||0).getTime()>cutoff48h;
          const samePhone=x.phone1===o.phone1||x.phone1===o.phone2||x.phone2===o.phone1;
          const sameAddr=x.wilaya===o.wilaya&&x.commune===o.commune&&x.name===o.name;
          return isRecent&&(samePhone||sameAddr)&&x.id!==o.id;
        });
        if(prevOrder){
          o.repeated=true;
          o.prevOrderId=prevOrder.id;
          await sendPush(env,"طلبية مكررة","هاتف: "+o.phone1+" | "+o.wilaya+" | سابقة: "+prevOrder.id);
          await logActivity(env,"duplicate_order","طلبية مكررة: "+o.id+" (سابقة: "+prevOrder.id+")");
        }

        o.refDisc=refDisc;o.total=(o.total||total)-refDisc;

        // م12: سجل إنشاء الطلب
        o.auditTrail=[{t:new Date().toISOString(),type:"create",actor:"customer",total:o.total}];

        // نقاط الولاء
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
        if(!o.repeated)await sendPush(env,"طلبية جديدة","من: "+o.name+" | "+o.wilaya+" | "+o.total.toLocaleString()+" دج");
        return RR({ok:true,orderId:o.id,total:o.total,finalSub,fee,discAmt,ccpDisc,couponDisc,globalDiscount:appliedGlobalDisc,repeated:o.repeated||false});
      }

      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="GET")return RR(await kvGet(env,"orders",[]));
      if(method==="PATCH"){
        const body=await request.json(),orders=await kvGet(env,"orders",[]);
        const i=orders.findIndex(o=>o.id===body.id);
        if(i<0)return RR({error:"Not found"},404);
        const hist=orders[i].history||[];
        const auditTrail=orders[i].auditTrail||[];
        const ts=new Date().toISOString().replace("T"," ").slice(0,16);
        if(body.confirmed!==undefined){
          const old=orders[i].confirmed;orders[i].confirmed=body.confirmed;
          if(old!==body.confirmed){
            const txt=body.confirmed?"تم التأكيد":"الغاء التأكيد";
            hist.push({t:ts,txt});
            auditTrail.unshift({t:new Date().toISOString(),type:"confirmed",val:body.confirmed,actor:body.actor||"admin"});
          }
        }
        if(body.status){
          if(orders[i].status!==body.status){
            hist.push({t:ts,txt:"حالة: "+orders[i].status+" > "+body.status});
            auditTrail.unshift({t:new Date().toISOString(),type:"status",from:orders[i].status,to:body.status,actor:body.actor||"admin"});
            await logActivity(env,"order_status",orders[i].id+": "+orders[i].status+" > "+body.status,body.actor||"admin");
          }
          orders[i].status=body.status;
        }
        if(body.note!==undefined){
          auditTrail.unshift({t:new Date().toISOString(),type:"note",actor:body.actor||"admin"});
          orders[i].note=(body.note||"").substring(0,300);
        }
        // م37: تحديث سعر التكلفة والأرباح
        if(body.costPrice!==undefined){
          orders[i].costPrice=Math.max(0,parseInt(body.costPrice)||0);
          auditTrail.unshift({t:new Date().toISOString(),type:"cost_update",val:orders[i].costPrice,actor:body.actor||"admin"});
        }
        orders[i].history=hist.slice(0,30);
        orders[i].auditTrail=auditTrail.slice(0,50);
        await kvSet(env,"orders",orders);
        return RR(orders[i]);
      }
      if(method==="DELETE"){
        const delId=url.searchParams.get("id");
        if(delId){
          let orders=await kvGet(env,"orders",[]);
          const o=orders.find(x=>x.id===delId);
          orders=orders.filter(o=>o.id!==delId);
          await kvSet(env,"orders",orders);
          await logActivity(env,"order_delete","حذف طلبية: "+delId);
        }else{
          await kvSet(env,"orders",[]);
          await logActivity(env,"orders_clear","حذف كل الطلبيات");
        }
        return RR({ok:true});
      }
    }

    // ── تتبع الطلبية (عميل) ──
    if(path==="/api/track"&&method==="POST"){
      const{orderId,phone}=await request.json().catch(()=>({}));
      const orders=await kvGet(env,"orders",[]);
      const o=orders.find(x=>x.id===orderId||(phone&&x.phone1===phone));
      if(!o)return RR({ok:false,msg:"لم يتم العثور على هذه الطلبية"});
      return RR({ok:true,id:o.id,status:o.status||"processing",confirmed:o.confirmed,date:o.date,wilaya:o.wilaya,name:o.name});
    }

    // ── م2: الإحصائيات والزيارات ──
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
        await logActivity(env,"visits_cleanup","حذف "+deleted+" سجل ("+range+")");
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
        // م37: حساب هوامش الربح
        const totalCost=orders.filter(o=>o.confirmed&&o.status!=="returned")
          .reduce((a,o)=>{
            const itemsCost=(o.items||[]).reduce((s,it)=>{
              const prod=prods.find(p=>String(p.id)===String(it.id));
              return s+(prod?.costPrice||0)*(it.qty||1);
            },0);
            return a+itemsCost+(o.fee||0);
          },0);
        const grossProfit=rev-totalCost;
        const profitMargin=rev>0?Math.round(grossProfit/rev*100):0;
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
        orders.filter(o=>o.confirmed).forEach(o=>(o.items||[]).forEach(it=>{
          if(!salesMap[it.id])salesMap[it.id]={id:it.id,name:it.name||"",qty:0,img:it.img||""};
          salesMap[it.id].qty+=it.qty||1;
        }));
        const salesArr=Object.values(salesMap).sort((a,b)=>b.qty-a.qty);
        const bestProd=salesArr[0]||null;
        const wilayaMap={};
        orders.filter(o=>o.confirmed).forEach(o=>{if(o.wilaya)wilayaMap[o.wilaya]=(wilayaMap[o.wilaya]||0)+1;});
        const bestWilaya=Object.entries(wilayaMap).sort((a,b)=>b[1]-a[1])[0]||null;
        const confirmRate=orders.length?Math.round(conf/orders.length*100):0;
        const avgOrderVal=conf?Math.round(rev/conf):0;
        const bounceRate=visits.length?Math.round(visits.filter(v=>v.bounced).length/visits.length*100):0;
        const dailySales={};
        for(let i=0;i<14;i++){const d=new Date(n-i*86400000).toISOString().slice(0,10);dailySales[d]={orders:0,revenue:0};}
        orders.filter(o=>o.confirmed).forEach(o=>{const k=o.date?o.date.slice(0,10):"";if(dailySales[k]){dailySales[k].orders++;dailySales[k].revenue+=(o.finalSub||o.total||0);}});
        return RR({totalVisits:visits.length,uniqueVisitors:uniq,totalOrders:orders.length,confirmedOrders:conf,
          revenue:rev,netRevenue,totalReturnCost,returnedCount:returnedOrders.length,productCount:prods.length,
          totalCost,grossProfit,profitMargin, // م37
          devMap,brandMap,tierMap,osMap,hourMap,bounceRate,confirmRate,avgOrderVal,
          revThisWeek:rTW,revLastWeek:rLW,revThisMonth:rTM,revLastMonth:rLM,
          ordersThisWeek:oTW.length,ordersLastWeek:oLW.length,ordersThisMonth:oTM.length,ordersLastMonth:oLM.length,
          bestProd,bestWilaya,dailySales,wilayaMap, // م16: بيانات الخريطة الجغرافية
          salesByProduct:salesArr.slice(0,20), // م32
          visitors:Object.entries(visMap).sort((a,b)=>b[1].count-a[1].count).slice(0,100).map(([vid,d])=>({vid,...d}))});
      }
    }

    // ── الإعدادات ──
    if(path==="/api/settings"){
      if(method==="GET")return RR(await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322",email:"wowastore15@gmail.com",instagram:"wow.dz4"}));
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
        trustItems:Array.isArray(rawS.trustItems)?rawS.trustItems.slice(0,8).map(x=>(x||"").substring(0,100)):[],
        trustBadges:rawS.trustBadges||{},
        // م38-م40: بيانات الثقة وسياسات المتجر
        featuresBar:Array.isArray(rawS.featuresBar)?rawS.featuresBar.slice(0,6).map(x=>(x||"").substring(0,100)):[],
        showFeatureBar:rawS.showFeatureBar!==false,
        showFaq:rawS.showFaq!==false,
        showRefundPolicy:rawS.showRefundPolicy!==false,
        showTrustBadges:rawS.showTrustBadges!==false,
        // م44: اللغة المتعددة
        storeNameEn:(rawS.storeNameEn||"").substring(0,80),
        storeNameFr:(rawS.storeNameFr||"").substring(0,80),
      };
      await kvSet(env,"settings",safeS);
      await logActivity(env,"settings_update","تعديل الإعدادات: "+Object.keys(rawS).join(","));
      return RR({ok:true});
    }

    // ── KV Stats ──
    if(path==="/api/kv-stats"&&method==="GET"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      const KV_MAX_BYTES=1*1024*1024*1024;
      const MAIN_KEYS=["products","orders","visits","settings","push_subscription","coupons","flash_sales","bundles","reviews","testimonials","archived_products","stock_history","activity_log","referrals","loyalty_index","waitlist","stories"];
      let totalBytes=0;const keyDetails=[];
      for(const k of MAIN_KEYS){
        try{const raw=await env.DATABASE.get(k);if(raw!==null){const b=new TextEncoder().encode(raw).length;totalBytes+=b;keyDetails.push({key:k,bytes:b});}}catch{}
      }
      try{const listed=await env.DATABASE.list({prefix:"admin_token:"});for(const {name} of listed.keys){try{const raw=await env.DATABASE.get(name);if(raw!==null){const b=new TextEncoder().encode(raw).length;totalBytes+=b;}}catch{}}if(listed.keys.length)keyDetails.push({key:"admin_token:* ("+listed.keys.length+")",bytes:listed.keys.length*40});}catch{}
      try{const fpList=await env.DATABASE.list({prefix:"fp:"});const fpBytes=fpList.keys.length*80;totalBytes+=fpBytes;if(fpList.keys.length)keyDetails.push({key:"fp:* ("+fpList.keys.length+")",bytes:fpBytes});}catch{}
      const usedMB=totalBytes/(1024*1024),pctUsed=Math.min(100,(totalBytes/KV_MAX_BYTES)*100);
      return RR({ok:true,usedBytes:totalBytes,usedMB:+usedMB.toFixed(3),totalMB:1024,pctUsed:+pctUsed.toFixed(2),pctFree:+(100-pctUsed).toFixed(2),keyDetails});
    }

    // ── Flash Sales ──
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

    // ── Bundles ──
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

    // ── Waitlist ──
    if(path==="/api/waitlist"){
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        if(!b.phone||!b.productId)return RR({error:"Missing fields"},400);
        const phone=(b.phone||"").replace(/\s/g,"").substring(0,15);
        if(!/^0[567]\d{8}$/.test(phone))return RR({error:"هاتف غير صالح"},400);
        const wl=await kvGet(env,"waitlist",[]);
        const exists=wl.find(w=>w.phone===phone&&w.productId===b.productId);
        if(exists)return RR({ok:true,msg:"انت مسجل بالفعل"});
        wl.push({phone,productId:b.productId,productName:(b.productName||"").substring(0,80),t:new Date().toISOString()});
        await kvSet(env,"waitlist",wl.slice(0,500));
        return RR({ok:true,msg:"سيتم تنبيهك حين يتوفر المنتج"});
      }
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="GET")return RR(await kvGet(env,"waitlist",[]));
      if(method==="DELETE"){
        const pid=url.searchParams.get("productId");
        let wl=await kvGet(env,"waitlist",[]);
        if(pid)wl=wl.filter(w=>w.productId!==pid&&w.productId!==+pid);else wl=[];
        await kvSet(env,"waitlist",wl);return RR({ok:true});
      }
    }

    // ── Loyalty ──
    if(path==="/api/loyalty"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="GET"){
        const phone=url.searchParams.get("phone");
        if(phone){const pts=await kvGet(env,"lp:"+phone,{points:0,history:[]});return RR(pts);}
        return RR(await kvGet(env,"loyalty_index",[]));
      }
    }

    // ── Referrals ──
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
      return RR(`<html dir="rtl" lang="ar"><head><meta charset="UTF-8"><title>رابط الاحالة</title></head><body style="font-family:sans-serif;text-align:center;padding:40px;background:#0a0016;color:#e0d0ff"><h2 style="color:#c084fc">رابط الاحالة الخاص بك</h2><p style="color:#888;margin-bottom:20px">ارسل هذا الرابط لاصدقائك واحصل على خصم 5%</p><div id="rl" style="background:#1a0a2e;border:1px solid #6d28d9;border-radius:10px;padding:16px;font-size:14px;letter-spacing:1px;color:#c084fc;word-break:break-all">${_refFullLink}</div><button onclick="navigator.clipboard.writeText(document.getElementById('rl').textContent)" style="margin-top:20px;background:#6d28d9;color:#fff;border:none;border-radius:8px;padding:10px 24px;cursor:pointer;font-size:14px">نسخ الرابط</button></body></html>`,200,{"Content-Type":"text/html;charset=utf-8"});
    }

    // ── Reviews ──
    if(path==="/api/reviews"){
      if(method==="GET"){
        const pid=url.searchParams.get("productId");
        const reviews=await kvGet(env,"reviews",[]);
        return RR(pid?reviews.filter(r=>String(r.productId)===String(pid)&&r.approved):reviews);
      }
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        if(!b.productId||!b.rating||!b.name)return RR({error:"Missing fields"},400);
        const reviews=await kvGet(env,"reviews",[]);
        // م30: التحقق من طلبية حقيقية (ربط رقم الهاتف بطلبية مؤكدة)
        if(b.phone){
          if(reviews.find(r=>r.phone===b.phone&&String(r.productId)===String(b.productId)))
            return RR({error:"لقد قيمت هذا المنتج مسبقا"},400);
        }
        const rev={id:Date.now(),productId:b.productId,
          name:(b.name||"").substring(0,60),phone:(b.phone||"").substring(0,15),
          rating:Math.max(1,Math.min(5,parseInt(b.rating)||5)),
          body:(b.body||"").substring(0,300),
          t:new Date().toISOString(),approved:false};
        reviews.push(rev);await kvSet(env,"reviews",reviews.slice(0,2000));
        return RR({ok:true,msg:"تم ارسال تقييمك وسيظهر بعد المراجعة"});
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

    // ── Testimonials ──
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

    // ── م5: كوبونات — إضافة شروط متقدمة ──
    if(path==="/api/coupons"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="GET")return RR(await kvGet(env,"coupons",[]));
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        const code=(b.code||"").toUpperCase().replace(/[^A-Z0-9]/g,"").substring(0,20);
        if(!code)return RR({error:"كود غير صالح"},400);
        const coupons=await kvGet(env,"coupons",[]);
        if(coupons.find(c=>c.code===code))return RR({error:"الكود موجود مسبقا"},400);
        const discType=b.discType==="fixed"?"fixed":"percent";
        let discVal=Math.max(0,parseFloat(b.discVal)||0);
        if(discType==="percent")discVal=Math.min(11,discVal);else discVal=Math.min(500,discVal);
        const c={
          id:Date.now(),code,discType,discVal,
          maxUses:b.maxUses?parseInt(b.maxUses)||0:0,
          usedCount:0,
          expiresAt:b.expiresAt||null,
          active:true,
          createdAt:new Date().toISOString(),
          minSub:Math.max(0,parseInt(b.minSub)||0), // م5: الحد الأدنى للسلة
          wilayas:Array.isArray(b.wilayas)?b.wilayas.slice(0,58):[], // م5: تقييد الولاية
          revenue:0, // م5: تتبع أرباح الكوبون
          ordersUsed:[] // م5: سجل الطلبيات
        };
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

    // م5: فحص الكوبون العام مع الشروط المتقدمة
    if(path==="/api/coupon-check"&&method==="POST"){
      const{code,sub,wilaya}=await request.json().catch(()=>({}));
      if(!code)return RR({ok:false,msg:"ادخل كود الخصم"});
      const coupons=await kvGet(env,"coupons",[]);
      const c=coupons.find(x=>x.code===(code||"").toUpperCase()&&x.active);
      if(!c)return RR({ok:false,msg:"الكود غير صالح"});
      if(c.expiresAt&&Date.now()>new Date(c.expiresAt).getTime())return RR({ok:false,msg:"الكود منتهي الصلاحية"});
      if(c.maxUses>0&&c.usedCount>=c.maxUses)return RR({ok:false,msg:"تم استنفاد هذا الكود"});
      if(c.minSub&&(parseFloat(sub)||0)<c.minSub)return RR({ok:false,msg:"الحد الادنى للطلب: "+c.minSub+" دج"});
      if(Array.isArray(c.wilayas)&&c.wilayas.length>0&&wilaya&&!c.wilayas.includes(wilaya))
        return RR({ok:false,msg:"هذا الكود غير متاح في ولايتك"});
      const orderSub=parseFloat(sub)||0;
      let discAmt=0;
      if(c.discType==="percent")discAmt=Math.round(orderSub*(c.discVal/100));
      else discAmt=Math.min(c.discVal,orderSub);
      return RR({ok:true,code:c.code,discType:c.discType,discVal:c.discVal,discAmt,msg:"تم تطبيق الخصم"});
    }

    // ── سجل المخزون ──
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
        hist.unshift({
          t:new Date().toISOString(),
          productId:prods[pi].id,
          productName:prods[pi].name||"",
          type:"manual",
          qty,
          reason:(b.reason||"تعديل يدوي").substring(0,100), // م25: سبب التعديل
          balanceAfter:prods[pi].quantity
        });
        await kvSet(env,"stock_history",hist.slice(0,1000));
        await logActivity(env,"stock_add","اضافة "+qty+" قطعة: "+prods[pi].name+" — "+b.reason);
        return RR({ok:true,newQty:prods[pi].quantity});
      }
    }

    // ── م35: سجل العمليات — فلترة حسب النوع ──
    if(path==="/api/activity-log"&&method==="GET"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      const typeFilter=url.searchParams.get("type");
      const actorFilter=url.searchParams.get("actor");
      let log=await kvGet(env,"activity_log",[]);
      if(typeFilter)log=log.filter(e=>e.type===typeFilter);
      if(actorFilter)log=log.filter(e=>e.actor===actorFilter);
      return RR(log.slice(0,500));
    }

    // ── م1: صفحة الفاتورة مع خيارات التخصيص ──
    if(path==="/invoice"&&method==="GET"){
      if(!await isAdmin(request,env))return RR("Unauthorized",401);
      const oid=url.searchParams.get("id");if(!oid)return RR("Missing id",400);
      const orders=await kvGet(env,"orders",[]);const o=orders.find(x=>x.id===oid);
      if(!o)return RR("Not found",404);
      const sets=await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322"});
      // تسجيل وقت طباعة الفاتورة
      const idx=orders.findIndex(x=>x.id===oid);
      if(idx>=0){
        orders[idx].lastPrintAt=new Date().toISOString();
        orders[idx].printCount=(orders[idx].printCount||0)+1;
        await kvSet(env,"orders",orders);
      }
      const opts={
        hideShipping:url.searchParams.get("hideShipping")==="1",
        extraNote:url.searchParams.get("note")||""
      };
      return new Response(buildInvoiceHTML(o,sets,opts),{headers:{"Content-Type":"text/html;charset=utf-8","Cache-Control":"no-store"}});
    }

    // ── م6: بوليصة الشحن ──
    if(path==="/shipping-label"&&method==="GET"){
      if(!await isAdmin(request,env))return RR("Unauthorized",401);
      const oid=url.searchParams.get("id");const fmt=url.searchParams.get("fmt")||"yalidine";
      if(!oid)return RR("Missing id",400);
      const orders=await kvGet(env,"orders",[]);const o=orders.find(x=>x.id===oid);
      if(!o)return RR("Not found",404);
      const sets=await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322"});
      return new Response(buildShippingLabel(o,sets,fmt),{headers:{"Content-Type":"text/html;charset=utf-8","Cache-Control":"no-store"}});
    }

    // ── م13: طباعة جماعية للفواتير ──
    if(path==="/api/bulk-print"&&method==="POST"){
      if(!await isAdmin(request,env))return RR("Unauthorized",401);
      const{ids,type}=await request.json().catch(()=>({}));
      if(!Array.isArray(ids)||ids.length===0)return RR({error:"No IDs"},400);
      const orders=await kvGet(env,"orders",[]);
      const sets=await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322"});
      const selected=ids.slice(0,50).map(id=>orders.find(o=>o.id===id)).filter(Boolean);
      if(!selected.length)return RR({error:"No orders found"},404);
      const html=buildBulkPrintHTML(selected,sets);
      return new Response(html,{headers:{"Content-Type":"text/html;charset=utf-8","Cache-Control":"no-store"}});
    }

    // ── م43: إعادة ترتيب المنتجات (Drag & Drop) ──
    if(path==="/api/products/reorder"&&method==="POST"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      const{ids}=await request.json().catch(()=>({}));
      if(!Array.isArray(ids))return RR({error:"Invalid"},400);
      const prods=await kvGet(env,"products",[]);
      const sorted=ids.map(id=>prods.find(p=>String(p.id)===String(id))).filter(Boolean);
      const rest=prods.filter(p=>!ids.find(id=>String(id)===String(p.id)));
      await kvSet(env,"products",[...sorted,...rest]);
      await logActivity(env,"product_reorder","اعادة ترتيب "+sorted.length+" منتج");
      return RR({ok:true});
    }

    // ── Stories ──
    if(path==="/api/stories"){
      if(method==="GET")return RR((await kvGet(env,"stories",[])).filter(s=>s.active));
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        const stories=await kvGet(env,"stories",[]);
        stories.push({id:Date.now(),title:(b.title||"").substring(0,100),
          body:(b.body||"").substring(0,1000),img:(b.img||"").substring(0,500),
          active:true,createdAt:new Date().toISOString()});
        await kvSet(env,"stories",stories.slice(0,50));return RR({ok:true});
      }
      if(method==="DELETE"){
        const sid=+url.searchParams.get("id");
        let stories=await kvGet(env,"stories",[]);
        stories=stories.filter(s=>s.id!==sid);
        await kvSet(env,"stories",stories);return RR({ok:true});
      }
    }

    // ── صفحة About ──
    if(path==="/about"){
      const sets=await kvGet(env,"settings",{storeName:"WOW Store"});
      const about=sets.about||"";
      const sn=_escSrv(sets.storeName||"WOW STORE");
      return RR(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>عن ${sn}</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0016;color:#e0d0ff;padding:20px;min-height:100vh}.wrap{max-width:680px;margin:0 auto;padding:30px 0}.brand{font-family:Georgia,serif;font-size:40px;font-weight:900;letter-spacing:7px;color:#c084fc;text-align:center;margin-bottom:8px}.sub{text-align:center;font-size:11px;color:rgba(255,255,255,.25);letter-spacing:4px;margin-bottom:40px}.body{font-size:14px;line-height:2;color:rgba(255,255,255,.65)}.back{display:inline-block;margin-bottom:24px;color:rgba(168,85,247,.7);font-size:12px;cursor:pointer;text-decoration:none;border:1px solid rgba(168,85,247,.2);padding:6px 14px;border-radius:7px}</style></head><body><div class="wrap"><a class="back" href="/">&#8594; العودة للمتجر</a><div class="brand">${sn}</div><div class="sub">ABOUT US</div><div class="body">${about.replace(/\n/g,"<br>")}</div></div></body></html>`,200,{"Content-Type":"text/html;charset=utf-8"});
    }

    // ── م29: رابط المنتج الذكي مع Open Graph ──
    if(path.startsWith("/p/")){
      const pid=path.slice(3);
      const prods=await kvGet(env,"products",[]);
      const p=prods.find(x=>String(x.id)===pid);
      const sets=await kvGet(env,"settings",{storeName:"WOW Store"});
      const img=(p&&p.images&&p.images[0])||"";
      const sn=_escSrv(sets.storeName||"WOW Store");
      const pname=p?_escSrv(p.name||""):"منتج";
      const pdesc=p?_escSrv(p.desc||""):"تسوق الآن";
      const purl=url.origin+"/p/"+pid;
      return RR(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<title>${pname} — ${sn}</title>
<meta property="og:title" content="${pname} — ${sn}">
<meta property="og:description" content="${pdesc}">
<meta property="og:type" content="product">
${img?`<meta property="og:image" content="${_escSrv(img)}">`:``}
<meta property="og:url" content="${purl}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${pname}">
<meta name="twitter:description" content="${pdesc}">
${img?`<meta name="twitter:image" content="${_escSrv(img)}">`:``}
<script>window.location.replace("/?openProd=${pid}");</script>
</head><body style="background:#0a0016;color:#c084fc;font-family:sans-serif;text-align:center;padding:40px">
<p>...</p><a href="/" style="color:#a855f7">العودة للمتجر</a>
</body></html>`,200,{"Content-Type":"text/html;charset=utf-8"});
    }

    // ── صفحة Stories ──
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
      return RR(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>قصص النجاح — ${sn}</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0016;color:#e0d0ff;padding:20px;min-height:100vh}.wrap{max-width:700px;margin:0 auto}.brand{font-family:Georgia,serif;font-size:36px;font-weight:900;letter-spacing:6px;color:#c084fc;text-align:center;margin-bottom:6px}.sub{text-align:center;font-size:10px;color:rgba(255,255,255,.25);letter-spacing:4px;margin-bottom:36px}a.back{display:inline-block;margin-bottom:20px;color:rgba(168,85,247,.7);font-size:12px;border:1px solid rgba(168,85,247,.2);padding:6px 14px;border-radius:7px;text-decoration:none}</style></head>
<body><div class="wrap"><a class="back" href="/">&#8594; العودة للمتجر</a><div class="brand">${sn}</div><div class="sub">SUCCESS STORIES</div>${cards||"<p style='text-align:center;color:rgba(255,255,255,.3);padding:40px'>لا توجد قصص بعد</p>"}</div></body></html>`,200,{"Content-Type":"text/html;charset=utf-8"});
    }

    // ── API Docs ──
    if(path==="/api-docs"&&method==="GET"){
      if(!await isAdmin(request,env))return RR("Unauthorized",401);
      const sets=await kvGet(env,"settings",{storeName:"WOW Store"});
      const sn=_escSrv(sets.storeName||"WOW Store");
      const endpoints=[
        ["GET","/api/products","جلب المنتجات (مع Flash Sales)","public"],
        ["POST","/api/products","انشاء منتج","admin"],
        ["PUT","/api/products","تعديل منتج","admin"],
        ["DELETE","/api/products?id=X&archive=1","حذف/ارشفة منتج","admin"],
        ["POST","/api/products/reorder","اعادة ترتيب","admin"],
        ["POST","/api/products/track","تتبع زيارات/سلة","public"],
        ["GET/POST","/api/products/archive","المؤرشفة + استعادة جماعية","admin"],
        ["GET","/api/orders","الطلبيات","admin"],
        ["POST","/api/orders","طلبية جديدة (مع كشف تكرار)","public"],
        ["PATCH","/api/orders","تعديل حالة (Audit Trail)","admin"],
        ["DELETE","/api/orders","حذف طلبية","admin"],
        ["POST","/api/bulk-print","طباعة جماعية","admin"],
        ["GET/POST/PATCH/DELETE","/api/coupons","كوبونات (+ شروط متقدمة)","admin"],
        ["POST","/api/coupon-check","فحص كوبون Ajax","public"],
        ["GET/POST/DELETE","/api/flash-sales","Flash Sales","admin"],
        ["GET/POST/PATCH/DELETE","/api/bundles","الحزم","admin"],
        ["GET/POST/DELETE","/api/waitlist","قائمة الانتظار","admin/public"],
        ["GET","/api/loyalty","نقاط الولاء","admin"],
        ["GET/POST/PATCH/DELETE","/api/reviews","التقييمات","admin/public"],
        ["GET/POST/DELETE","/api/testimonials","الشهادات","admin"],
        ["GET/POST/DELETE","/api/stories","القصص","admin/public"],
        ["GET/POST/DELETE","/api/analytics","الاحصائيات (+ KPIs + Profit)","admin/public"],
        ["GET","/api/activity-log","سجل العمليات (قابل للفلترة)","admin"],
        ["GET/POST","/api/stock-history","تاريخ المخزون","admin"],
        ["GET/POST","/api/settings","الاعدادات (+ بيانات الثقة)","admin"],
        ["GET","/api/kv-stats","احصائيات KV","admin"],
        ["GET","/invoice?id=X&hideShipping=1&note=X","فاتورة HTML مخصصة","admin"],
        ["GET","/shipping-label?id=X&fmt=Y","بوليصة شحن","admin"],
        ["GET","/refer?p=PHONE","رابط احالة","public"],
        ["GET","/about","عن المتجر","public"],
        ["GET","/stories","قصص النجاح","public"],
        ["GET","/p/:id","رابط منتج + OG tags","public"],
      ];
      return RR(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>API Docs — ${sn}</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',monospace;background:#0a0016;color:#e0d0ff;padding:20px}h1{font-family:Georgia,serif;font-size:24px;color:#c084fc;margin-bottom:4px}.sub{font-size:10px;color:rgba(255,255,255,.3);letter-spacing:2px;margin-bottom:24px}.ep{background:rgba(255,255,255,.02);border:1px solid rgba(168,85,247,.12);border-radius:9px;padding:11px 13px;margin-bottom:9px}.method{display:inline-block;padding:2px 8px;border-radius:4px;font-size:9px;font-weight:700;margin-left:8px;letter-spacing:1px}.get{background:rgba(34,197,94,.12);color:rgba(74,222,128,.9)}.post{background:rgba(99,102,241,.12);color:rgba(165,180,252,.9)}.patch{background:rgba(251,191,36,.12);color:rgba(253,224,71,.9)}.del{background:rgba(239,68,68,.12);color:rgba(252,165,165,.9)}.path{font-family:monospace;font-size:12px;color:rgba(192,132,252,.9)}.desc{font-size:10px;color:rgba(255,255,255,.45);margin-top:4px}.auth{font-size:9px;color:rgba(251,191,36,.6);margin-top:2px}</style></head>
<body><h1>${sn} API</h1><div class="sub">v12.0 — ${endpoints.length} endpoints</div>
${endpoints.map(([m,p,d,a])=>{const cls=m.toLowerCase().startsWith('get')?'get':m.toLowerCase().startsWith('post')?'post':m.toLowerCase().startsWith('patch')?'patch':'del';return`<div class="ep"><span class="method ${cls}">${m}</span><span class="path">${p}</span><div class="desc">${d}</div><div class="auth">${a}</div></div>`}).join("")}
</body></html>`,200,{"Content-Type":"text/html;charset=utf-8"});
    }

    // ── الصفحة الرئيسية ──
    const settings=await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322",email:"wowastore15@gmail.com",instagram:"wow.dz4"});
    return RR(buildHTML(settings),200,{"Cache-Control":"public,max-age=60","X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY"});
    }catch(err){
      console.error("Worker error:",err);
      return new Response(JSON.stringify({error:"Internal error"}),{status:500,headers:{"Content-Type":"application/json"}});
    }
  }
};

// ═══════════════════════════════════════════════════════════════
// buildHTML — واجهة المتجر + لوحة التحكم الكاملة
// ═══════════════════════════════════════════════════════════════
function buildHTML(s){
  const sn=s.storeName||"WOW Store";
  const wa=(s.whatsapp||"0667881322").replace(/[^0-9+]/g,"");
  const em=s.email||"wowastore15@gmail.com";
  const ig=s.instagram||"wow.dz4";
  const adminDisc=Math.max(0,Math.min(90,parseInt(s.admin_discount||0)||0));
  const lang=["ar","fr","en"].includes(s.lang)?s.lang:"ar";
  const isRTL=lang==="ar";
  const featuresBar=Array.isArray(s.featuresBar)&&s.featuresBar.length
    ?s.featuresBar:["شحن لكل الولايات","ضمان الجودة","دفع عند الاستلام"];
  const showFeatBar=s.showFeatureBar!==false;
  const featBarHTML=showFeatBar
    ?`<div class="feat-bar">${featuresBar.map(f=>`<span class="feat-item">${f}</span>`).join("")}</div>`:"";
  const WILAYAS=["ادرار","الشلف","الاغواط","ام البواقي","باتنة","بجاية","بسكرة","بشار","البليدة","البويرة","تمنراست","تبسة","تلمسان","تيارت","تيزي وزو","الجزائر","الجلفة","جيجل","سطيف","سعيدة","سكيكدة","سيدي بلعباس","عنابة","قالمة","قسنطينة","المدية","مستغانم","المسيلة","معسكر","ورقلة","وهران","البيض","اليزي","برج بوعريريج","بومرداس","الطارف","تندوف","تيسمسيلت","الوادي","خنشلة","سوق اهراس","تيبازة","ميلة","عين الدفلى","النعامة","عين تموشنت","غرداية","غليزان","تيميمون","طولقة","بني عباس","عين صالح","عين قزام","تقرت","جانت","المغير","المنيعة","وادي سوف"];
  const wilayaOpts=WILAYAS.map(w=>`<option value="${w}">${w}</option>`).join("");
  const SF_OBJ={ادرار:{h:1700,d:900},الشلف:{h:1100,d:700},الاغواط:{h:1300,d:800},"ام البواقي":{h:1100,d:700},باتنة:{h:1100,d:700},بجاية:{h:1100,d:700},بسكرة:{h:1300,d:800},بشار:{h:1400,d:900},البليدة:{h:1100,d:700},البويرة:{h:1100,d:700},تمنراست:{h:2200,d:1300},تبسة:{h:800,d:500},تلمسان:{h:1200,d:700},تيارت:{h:1200,d:700},"تيزي وزو":{h:1100,d:700},الجزائر:{h:1100,d:700},الجلفة:{h:1300,d:800},جيجل:{h:1100,d:700},سطيف:{h:1100,d:700},سعيدة:{h:1200,d:700},سكيكدة:{h:1100,d:700},"سيدي بلعباس":{h:1100,d:700},عنابة:{h:1100,d:700},قالمة:{h:1100,d:700},قسنطينة:{h:1100,d:700},المدية:{h:1100,d:700},مستغانم:{h:1100,d:700},المسيلة:{h:1100,d:700},معسكر:{h:1100,d:700},ورقلة:{h:1300,d:800},وهران:{h:1100,d:700},البيض:{h:1400,d:900},اليزي:{h:2200,d:1300},"برج بوعريريج":{h:1100,d:700},بومرداس:{h:1100,d:700},الطارف:{h:1100,d:700},تندوف:{h:1900,d:1200},تيسمسيلت:{h:1100,d:700},الوادي:{h:1300,d:800},خنشلة:{h:1100,d:700},"سوق اهراس":{h:1100,d:700},تيبازة:{h:1100,d:700},ميلة:{h:1100,d:700},"عين الدفلى":{h:1100,d:700},النعامة:{h:1400,d:800},"عين تموشنت":{h:1100,d:700},غرداية:{h:1300,d:800},غليزان:{h:1200,d:700},تيميمون:{h:1700,d:1100},طولقة:{h:1300,d:900},"بني عباس":{h:1400,d:900},"عين صالح":{h:2200,d:1300},"عين قزام":{h:2200,d:1300},تقرت:{h:1300,d:800},جانت:{h:2500,d:1400},المغير:{h:1300,d:800},المنيعة:{h:1300,d:800},"وادي سوف":{h:1300,d:800}};
  const sfJSON=JSON.stringify(SF_OBJ);
  return `<!DOCTYPE html>
<html lang="${lang}" dir="${isRTL?"rtl":"ltr"}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#050505">
<title>${sn}</title>
<meta name="description" content="${sn}">
<meta property="og:title" content="${sn}">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#050505;--p1:rgba(255,255,255,.04);--b1:rgba(255,255,255,.08);--ac:#a855f7;--tx:rgba(255,255,255,.88);--dim:rgba(255,255,255,.4);--mu:rgba(255,255,255,.22);--r:16px;--rs:10px;--safe-bottom:env(safe-area-inset-bottom,0px)}
html{scroll-behavior:smooth}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--tx);overflow-x:hidden;min-height:100vh}
/* ── Ambient ── */
.vignette{position:fixed;inset:0;pointer-events:none;z-index:9996;background:radial-gradient(ellipse 90% 90% at 50% 50%,transparent 55%,rgba(0,0,0,.45) 100%)}
.ambient-bg{position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(ellipse 75% 55% at 30% 40%,rgba(88,28,135,.05),transparent 60%),radial-gradient(ellipse 55% 45% at 70% 60%,rgba(55,48,163,.035),transparent 55%)}
/* ── Scroll progress ── */
#scroll-prog{position:fixed;top:0;right:0;left:0;height:2px;background:linear-gradient(90deg,#6d28d9,#a855f7,#c084fc);transform-origin:right;transform:scaleX(0);z-index:9999;transition:transform .08s linear}
/* ── م38: شريط الميزات ── */
.feat-bar{display:flex;flex-wrap:wrap;justify-content:center;background:rgba(109,40,217,.06);border-bottom:1px solid rgba(168,85,247,.1);padding:6px 16px;overflow:hidden}
.feat-item{font-size:10px;color:rgba(168,85,247,.7);letter-spacing:1.5px;padding:2px 12px;border-left:1px solid rgba(168,85,247,.15);white-space:nowrap}
.feat-item:first-child{border-left:none}
/* ── Hero ── */
.hero-bg{position:relative;width:100%;overflow:hidden;z-index:3;min-height:160px;max-height:70vh;background:#050505}
.hero-bg-media{width:100%;height:auto;display:block;object-fit:contain;object-position:center;z-index:1;position:relative}
.hero-bg-media.is-img{width:100%;height:36vh;min-height:180px;max-height:320px;object-fit:cover}
.hero-bg-fallback{position:absolute;inset:0;background:linear-gradient(135deg,rgba(88,28,135,.35) 0%,rgba(5,5,5,.98) 100%);z-index:0}
.hero-bg-overlay{position:absolute;inset:0;background:linear-gradient(180deg,rgba(5,5,5,.15) 0%,rgba(5,5,5,.5) 100%);z-index:2;pointer-events:none}
/* ── Header ── */
.hdr{position:sticky;top:0;z-index:200;background:rgba(3,0,8,.94);backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px);border-bottom:1px solid rgba(168,85,247,.1);transition:box-shadow .3s,border-color .3s}
.hdr.scrolled{border-bottom-color:rgba(168,85,247,.22);box-shadow:0 4px 40px rgba(0,0,0,.7)}
.hdr-i{max-width:1200px;margin:0 auto;padding:10px 16px;display:flex;align-items:center;gap:10px}
.logo{display:flex;align-items:center;text-decoration:none;flex-shrink:0;cursor:pointer;-webkit-tap-highlight-color:transparent;transition:filter .3s,transform .28s cubic-bezier(.34,1.2,.64,1)}
.logo:hover{filter:drop-shadow(0 0 10px rgba(192,132,252,.4));transform:scale(1.04)}
.search-wrap{flex:1;max-width:320px;position:relative}
.search-inp{width:100%;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:var(--rs);color:var(--tx);font-family:inherit;font-size:12px;padding:8px 34px 8px 12px;outline:none;transition:border-color .22s,background .22s,box-shadow .22s;-webkit-appearance:none}
.search-inp::placeholder{color:var(--mu)}
.search-inp:focus{border-color:rgba(168,85,247,.5);background:rgba(168,85,247,.06);box-shadow:0 0 0 3px rgba(168,85,247,.1)}
.search-ico{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--mu);font-size:13px;pointer-events:none}
.hdr-r{display:flex;align-items:center;gap:6px;flex-shrink:0;margin-right:auto}
/* ── Buttons ── */
.cart-btn{display:flex;align-items:center;gap:6px;background:rgba(168,85,247,.12);border:1px solid rgba(168,85,247,.25);border-radius:var(--rs);padding:8px 12px;cursor:pointer;color:rgba(192,132,252,.9);font-size:12px;font-weight:500;white-space:nowrap;font-family:inherit;transition:background .2s,transform .2s;-webkit-tap-highlight-color:transparent;touch-action:manipulation;min-height:40px}
.cart-btn:hover{background:rgba(168,85,247,.22);transform:translateY(-1px)}
.cart-btn:active{transform:scale(.97)}
.cbdg{background:var(--ac);color:#fff;font-size:9px;font-weight:700;width:16px;height:16px;border-radius:50%;display:flex;align-items:center;justify-content:center;border:2px solid var(--bg);transition:transform .3s cubic-bezier(.34,1.56,.64,1);flex-shrink:0}
.adm-btn{display:flex;align-items:center;gap:5px;background:rgba(255,255,255,.04);border:1px solid var(--b1);border-radius:8px;padding:7px 10px;cursor:pointer;color:var(--dim);font-size:11px;font-family:inherit;transition:background .18s,color .18s;-webkit-tap-highlight-color:transparent;min-height:40px;min-width:40px;justify-content:center}
.adm-btn:hover{background:rgba(255,255,255,.08);color:rgba(255,255,255,.6)}
/* ── Filters ── */
.flt-wrap{max-width:1200px;margin:0 auto;padding:14px 16px 6px;display:flex;gap:7px;overflow-x:auto;scrollbar-width:none;-webkit-overflow-scrolling:touch}
.flt-wrap::-webkit-scrollbar{display:none}
.flt-btn{flex-shrink:0;padding:6px 14px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:20px;color:var(--dim);font-size:11px;font-weight:500;cursor:pointer;font-family:inherit;transition:background .18s,border-color .18s,color .18s;-webkit-tap-highlight-color:transparent;touch-action:manipulation;min-height:36px}
.flt-btn:hover{background:rgba(168,85,247,.1);border-color:rgba(168,85,247,.3)}
.flt-btn.on{background:rgba(168,85,247,.18);border-color:rgba(168,85,247,.45);color:rgba(192,132,252,.95)}
/* ── Product Grid ── */
.grid{max-width:1200px;margin:0 auto;padding:0 16px 120px;display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:12px;position:relative;z-index:5}
@media(min-width:480px){.grid{grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:14px}}
@media(min-width:900px){.grid{grid-template-columns:repeat(auto-fill,minmax(220px,1fr))}}
/* ── Cards ── */
.card{background:rgba(10,5,18,.96);border:1px solid rgba(168,85,247,.1);border-radius:var(--r);overflow:hidden;display:flex;flex-direction:column;cursor:pointer;transition:transform .22s ease,box-shadow .22s ease,border-color .22s ease;position:relative;-webkit-tap-highlight-color:transparent;touch-action:manipulation}
.card:hover{transform:translateY(-4px);border-color:rgba(168,85,247,.25);box-shadow:0 14px 40px rgba(0,0,0,.55)}
.card:active{transform:translateY(-1px)}
.card.hidden{display:none!important}
/* ── Image Slider ── */
.img-slider{position:relative;overflow:hidden;aspect-ratio:3/4;background:#0a0016;border-radius:var(--r) var(--r) 0 0}
.img-slider img{width:100%;height:100%;object-fit:cover;filter:brightness(.82) saturate(.72);transition:filter .4s,opacity .3s;position:absolute;top:0;left:0;opacity:0}
.img-slider img.active{opacity:1;position:relative}
.img-slider img.lazy-blur{filter:brightness(.82) saturate(.72) blur(8px);transform:scale(1.03)}
.img-slider img.lazy-loaded{transition:filter .5s,transform .5s;filter:brightness(.82) saturate(.72) blur(0);transform:none}
.slide-arr{position:absolute;top:50%;transform:translateY(-50%);background:rgba(0,0,0,.52);border:none;color:#fff;width:28px;height:28px;border-radius:50%;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:15px;z-index:5;transition:background .18s,opacity .18s;opacity:0;-webkit-tap-highlight-color:transparent;touch-action:manipulation}
.img-slider:hover .slide-arr,.img-slider:focus-within .slide-arr{opacity:1}
.slide-arr.prev{right:5px}.slide-arr.next{left:5px}
.slide-arr:hover{background:rgba(168,85,247,.6)}
.slide-dots{position:absolute;bottom:5px;left:50%;transform:translateX(-50%);display:flex;gap:4px;z-index:5}
.slide-dot{width:5px;height:5px;border-radius:50%;background:rgba(255,255,255,.3);cursor:pointer;transition:background .18s,width .18s;-webkit-tap-highlight-color:transparent}
.slide-dot.on{background:rgba(192,132,252,.9);width:12px;border-radius:3px}
/* ── Flash Strip ── */
.card-flash-strip{position:absolute;top:0;left:0;right:0;background:linear-gradient(135deg,rgba(239,68,68,.18),rgba(251,191,36,.1));border-bottom:1px solid rgba(239,68,68,.2);padding:3px 8px;font-size:9px;color:rgba(252,165,165,.9);font-weight:700;z-index:6;display:flex;justify-content:space-between;align-items:center;letter-spacing:.5px}
/* ── Card Body ── */
.card-body{padding:10px;flex:1;display:flex;flex-direction:column;gap:4px;position:relative;z-index:2}
.card-cat{font-size:9px;color:rgba(168,85,247,.45);letter-spacing:2.5px;text-transform:uppercase}
.card-name{font-size:12px;color:rgba(255,255,255,.5);line-height:1.4;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.price-wrap{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-top:2px}
.card-price{font-family:Georgia,serif;font-size:15px;font-weight:700;color:rgba(192,132,252,.95)}
.card-price-old{font-size:11px;color:var(--mu);text-decoration:line-through}
.disc-badge{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.25);color:rgba(252,165,165,.85);font-size:9px;font-weight:700;padding:1px 6px;border-radius:4px}
.sales-counter{font-size:9px;color:rgba(74,222,128,.65);margin-top:2px}
/* ── Scarcity ── */
.scarcity-bar{height:3px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden;margin-top:3px}
.scarcity-fill{height:100%;border-radius:2px}
.scarcity-low{background:linear-gradient(90deg,#ef4444,#f97316)}
.scarcity-med{background:linear-gradient(90deg,#f59e0b,#fbbf24)}
.scarcity-txt{font-size:9px;color:rgba(252,165,165,.65);margin-top:2px}
/* ── Add Button ── */
.addbtn{background:rgba(109,40,217,.16);border:1px solid rgba(168,85,247,.25);border-radius:10px;color:rgba(216,180,254,.9);font-size:11px;font-weight:600;font-family:inherit;padding:9px 8px;cursor:pointer;transition:transform .22s cubic-bezier(.34,1.2,.64,1),background .22s,border-color .22s,box-shadow .22s;margin-top:7px;text-align:center;-webkit-tap-highlight-color:transparent;touch-action:manipulation;min-height:40px}
.addbtn:hover{background:rgba(109,40,217,.3);border-color:rgba(168,85,247,.52);transform:translateY(-2px);box-shadow:0 8px 24px rgba(109,40,217,.25)}
.addbtn:active{transform:scale(.96)}
/* ── Skeleton ── */
.skel-card{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.05);border-radius:var(--r);overflow:hidden}
.skel{background:linear-gradient(90deg,rgba(255,255,255,.04) 25%,rgba(168,85,247,.06) 50%,rgba(255,255,255,.04) 75%);background-size:200% 100%;animation:skel-sh 1.6s ease-in-out infinite}
@keyframes skel-sh{0%{background-position:200% 0}100%{background-position:-200% 0}}
.skel-img{aspect-ratio:3/4;border-radius:var(--r) var(--r) 0 0}
.skel-body{padding:10px;display:flex;flex-direction:column;gap:7px}
.skel-line{height:11px;border-radius:4px}
.skel-price{height:15px;width:55%;border-radius:4px}
.skel-btn{height:32px;border-radius:8px;margin-top:4px}
.empty{text-align:center;padding:50px 20px;color:var(--mu);font-size:12px;letter-spacing:2px;grid-column:1/-1}
/* ── Overlays ── */
.ov{position:fixed;inset:0;background:rgba(0,0,0,.58);backdrop-filter:blur(5px);-webkit-backdrop-filter:blur(5px);z-index:399;display:none;cursor:pointer;-webkit-tap-highlight-color:transparent}
.ov.on{display:block}
/* ── Cart Sidebar ── */
.cart-sb{position:fixed;top:0;right:-105%;width:360px;max-width:100vw;height:100%;background:rgba(8,6,16,.98);border-right:1px solid var(--b1);z-index:400;display:flex;flex-direction:column;transition:right .3s cubic-bezier(.4,0,.2,1)}
.cart-sb.on{right:0}
.cart-hdr{padding:14px 16px;border-bottom:1px solid var(--b1);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.cart-title{font-family:Georgia,serif;font-size:14px;color:rgba(192,132,252,.9);letter-spacing:3px}
.cart-items{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:8px;-webkit-overflow-scrolling:touch}
.cart-items::-webkit-scrollbar{width:3px}
.cart-items::-webkit-scrollbar-thumb{background:rgba(168,85,247,.3);border-radius:2px}
.c-empty{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:9px;color:var(--mu);font-size:12px}
.c-item{display:grid;grid-template-columns:52px 1fr auto;gap:8px;align-items:center;background:rgba(255,255,255,.03);border:1px solid var(--b1);border-radius:10px;padding:8px}
.c-img{width:52px;height:65px;object-fit:cover;border-radius:5px;filter:brightness(.8)}
.c-name{font-size:11px;color:rgba(255,255,255,.55);margin-bottom:3px;line-height:1.4}
.c-price{font-family:Georgia,serif;font-size:12px;color:rgba(192,132,252,.85)}
.c-sz{font-size:10px;color:var(--mu);margin-top:1px}
.rmbtn{background:none;border:none;color:rgba(255,255,255,.22);font-size:14px;cursor:pointer;padding:6px;border-radius:5px;transition:color .18s;-webkit-tap-highlight-color:transparent;min-width:32px;min-height:32px;display:flex;align-items:center;justify-content:center}
.rmbtn:hover{color:rgba(239,68,68,.7)}
.cart-ft{padding:12px 16px;border-top:1px solid var(--b1);display:flex;flex-direction:column;gap:9px;padding-bottom:calc(12px + var(--safe-bottom))}
.cart-tot{display:flex;justify-content:space-between;align-items:center}
.cart-tot-l{font-size:11px;color:var(--mu);letter-spacing:1px;text-transform:uppercase}
.cart-tot-v{font-family:Georgia,serif;font-size:18px;color:rgba(192,132,252,.9)}
/* ── Main Button ── */
.btn-main{background:linear-gradient(135deg,#6d28d9,#9333ea);border:none;border-radius:11px;color:#fff;font-family:inherit;font-size:12px;font-weight:600;padding:12px;cursor:pointer;transition:box-shadow .22s,transform .18s,opacity .18s;width:100%;-webkit-tap-highlight-color:transparent;touch-action:manipulation;min-height:44px}
.btn-main:hover{box-shadow:0 6px 22px rgba(109,40,217,.35)}
.btn-main:active{transform:scale(.98)}
.btn-main:disabled{opacity:.5;cursor:not-allowed;transform:none}
/* ── Modals ── */
.mod-ov{position:fixed;inset:0;width:100%;height:100%;background:rgba(0,0,0,.9);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);z-index:1000;display:none;align-items:flex-start;justify-content:center;padding:16px;overflow-y:auto;-webkit-overflow-scrolling:touch}
.mod-ov.on{display:flex}
.mod{background:rgba(8,6,16,.98);border:1px solid rgba(168,85,247,.18);border-radius:20px;padding:24px;width:100%;max-width:520px;animation:pop .3s cubic-bezier(.34,1.4,.64,1);position:relative;margin:auto;flex-shrink:0}
@keyframes pop{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
.mod-title{font-family:Georgia,serif;font-size:15px;color:rgba(192,132,252,.9);letter-spacing:2px;margin-bottom:18px;display:flex;align-items:center;justify-content:space-between}
.close-btn{background:none;border:none;color:var(--mu);cursor:pointer;font-size:18px;padding:4px;-webkit-tap-highlight-color:transparent;min-width:36px;min-height:36px;display:flex;align-items:center;justify-content:center;border-radius:6px;transition:color .18s,background .18s}
.close-btn:hover{color:rgba(255,255,255,.5);background:rgba(255,255,255,.06)}
/* ── Form Fields ── */
.fl{margin-bottom:12px}
.fl label{display:block;font-size:10px;font-weight:500;color:rgba(168,85,247,.75);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:5px}
.inp{width:100%;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:9px;color:rgba(255,255,255,.88);font-family:inherit;font-size:12px;padding:9px 12px;outline:none;transition:border-color .2s,background .2s,box-shadow .2s;-webkit-appearance:none;min-height:40px}
.inp::placeholder{color:rgba(255,255,255,.28)}
.inp:focus{border-color:rgba(168,85,247,.4);background:rgba(255,255,255,.06);box-shadow:0 0 0 3px rgba(168,85,247,.08)}
.inp option{background:#111}
/* ── Checkout Stepper ── */
.stepper{display:flex;align-items:center;justify-content:center;margin-bottom:20px}
.step-item{display:flex;flex-direction:column;align-items:center;gap:3px;flex:1;position:relative}
.step-item:not(:last-child)::after{content:"";position:absolute;top:12px;left:calc(-50% + 14px);right:calc(50% + 14px);height:1px;background:rgba(255,255,255,.1)}
.step-item.done::after{background:rgba(168,85,247,.5)}
.step-dot{width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;border:1.5px solid rgba(255,255,255,.12);color:var(--mu);transition:all .25s}
.step-item.active .step-dot{border-color:rgba(168,85,247,.8);color:rgba(192,132,252,.95);background:rgba(168,85,247,.15)}
.step-item.done .step-dot{border-color:rgba(74,222,128,.5);color:rgba(74,222,128,.8);background:rgba(74,222,128,.08)}
.step-lbl{font-size:8px;color:var(--mu);letter-spacing:.5px;text-align:center}
.step-item.active .step-lbl{color:rgba(192,132,252,.7)}
.chk-step{display:none}.chk-step.active{display:block}
.step-nav{display:flex;gap:9px;margin-top:14px}
.btn-back{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:11px;color:var(--dim);font-family:inherit;font-size:12px;font-weight:600;padding:11px;cursor:pointer;flex:1;transition:background .2s;-webkit-tap-highlight-color:transparent;min-height:44px}
.btn-back:hover{background:rgba(255,255,255,.08)}
/* ── Payment Options ── */
.pay-opt{display:flex;align-items:flex-start;gap:10px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:11px;padding:10px 12px;cursor:pointer;transition:background .2s,border-color .2s;-webkit-tap-highlight-color:transparent}
.pay-opt:has(input:checked){background:rgba(168,85,247,.08);border-color:rgba(168,85,247,.35)}
.pay-opt input[type=radio]{margin-top:3px;accent-color:var(--ac);flex-shrink:0;width:16px;height:16px;cursor:pointer}
.pay-opt-body{flex:1}
.pay-opt-title{font-size:12px;font-weight:600;color:rgba(255,255,255,.82);margin-bottom:2px}
.pay-opt-sub{font-size:10px;color:var(--mu)}
/* ── Order Preview ── */
.op{background:rgba(168,85,247,.06);border:1px solid rgba(168,85,247,.1);border-radius:11px;padding:12px;margin-bottom:12px}
.op-row{display:flex;justify-content:space-between;padding:3px 0;font-size:11px}
.op-l{color:var(--mu)}.op-v{color:rgba(255,255,255,.7)}
.op-tot{display:flex;justify-content:space-between;align-items:center;padding-top:8px;margin-top:6px;border-top:1px solid rgba(168,85,247,.15)}
.op-tl{font-family:Georgia,serif;font-size:11px;color:rgba(255,255,255,.55);letter-spacing:1px}
.op-tv{font-family:Georgia,serif;font-size:17px;color:rgba(192,132,252,.95)}
/* ── Gallery ── */
.gal{display:flex;flex-direction:column;gap:7px;margin-bottom:13px}
.gal-main{width:100%;aspect-ratio:3/4;border-radius:12px;overflow:hidden;background:#111}
.gal-main img{width:100%;height:100%;object-fit:cover;transition:opacity .3s}
.gal-thumbs{display:flex;gap:6px;overflow-x:auto;scrollbar-width:none;padding-bottom:3px;-webkit-overflow-scrolling:touch}
.gal-thumbs::-webkit-scrollbar{display:none}
.gal-thumb{width:54px;height:67px;object-fit:cover;border-radius:7px;cursor:pointer;border:2px solid transparent;transition:border-color .18s,filter .18s;filter:brightness(.65);flex-shrink:0;-webkit-tap-highlight-color:transparent}
.gal-thumb.on{border-color:rgba(168,85,247,.7);filter:brightness(1)}
/* ── Size & Color Buttons ── */
.sz-row{display:flex;gap:6px;flex-wrap:wrap}
.sz-btn{padding:6px 12px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:7px;color:var(--dim);font-size:12px;font-weight:600;cursor:pointer;font-family:inherit;-webkit-tap-highlight-color:transparent;min-height:36px;transition:all .18s}
.sz-btn:hover{border-color:rgba(168,85,247,.3);color:rgba(192,132,252,.8)}
.sz-btn.on{background:rgba(168,85,247,.2);border-color:rgba(168,85,247,.5);color:rgba(192,132,252,.95)}
/* ── Variants ── */
.var-chip{padding:5px 12px;background:rgba(255,255,255,.04);border:1px solid rgba(168,85,247,.15);border-radius:20px;font-size:11px;color:var(--dim);cursor:pointer;font-family:inherit;-webkit-tap-highlight-color:transparent;min-height:34px;transition:all .15s}
.var-chip:hover,.var-chip.on{background:rgba(168,85,247,.12);border-color:rgba(168,85,247,.4);color:rgba(192,132,252,.9)}
/* ── Reviews ── */
.rv-card{padding:11px 13px;border:1px solid var(--b1);border-radius:9px;margin-bottom:7px;background:rgba(255,255,255,.02)}
.rv-card-stars{font-size:12px;color:#f59e0b;margin-bottom:4px}
.rv-card-body{font-size:11px;color:var(--dim);line-height:1.6;margin-bottom:6px}
.rv-card-name{font-size:10px;color:var(--mu)}
.rv-pending{opacity:.5;border-style:dashed}
/* ── Trust Badges ── */
.trust-badges{display:flex;flex-wrap:wrap;justify-content:center;gap:12px;padding:10px 14px;border-top:1px solid rgba(255,255,255,.05)}
.trust-badge{display:flex;align-items:center;gap:5px;font-size:10px;color:rgba(255,255,255,.35);letter-spacing:.5px}
/* ── FAQ ── */
.faq-item{border-bottom:1px solid rgba(255,255,255,.06)}
.faq-q{padding:11px 14px;cursor:pointer;font-size:12px;color:rgba(192,132,252,.8);font-weight:600;display:flex;justify-content:space-between;align-items:center;-webkit-tap-highlight-color:transparent;min-height:44px;user-select:none}
.faq-a{padding:0 14px 11px;font-size:11px;color:rgba(255,255,255,.5);line-height:1.7;display:none}
/* ── QR ── */
.qr-wrap{display:inline-block;padding:12px;background:#fff;border-radius:10px}
/* ── Testimonials ── */
.tcard{background:rgba(255,255,255,.025);border:1px solid rgba(168,85,247,.1);border-radius:12px;padding:16px;min-width:220px;max-width:260px;flex-shrink:0}
.tcard-stars{color:#f59e0b;font-size:13px;margin-bottom:7px}
.tcard-body{font-size:11px;color:rgba(255,255,255,.6);line-height:1.7;margin-bottom:10px}
.tcard-name{font-size:10px;color:rgba(168,85,247,.7);font-weight:600}
/* ── Waitlist ── */
.waitlist-btn{display:block;width:100%;padding:9px;background:rgba(255,255,255,.04);border:1px dashed rgba(168,85,247,.2);border-radius:10px;color:rgba(192,132,252,.6);font-size:11px;cursor:pointer;text-align:center;font-family:inherit;transition:background .2s,border-color .2s;-webkit-tap-highlight-color:transparent;min-height:40px}
.waitlist-btn:hover{background:rgba(168,85,247,.06);border-color:rgba(168,85,247,.3)}
/* ── Bundle ── */
.bundle-card{background:rgba(109,40,217,.06);border:1px solid rgba(109,40,217,.2);border-radius:14px;padding:16px;cursor:pointer;-webkit-tap-highlight-color:transparent;transition:border-color .2s}
.bundle-card:hover{border-color:rgba(168,85,247,.4)}
.bundle-imgs{display:flex;gap:5px;margin-bottom:10px}
.bundle-img{width:50px;height:62px;object-fit:cover;border-radius:7px;border:1px solid rgba(168,85,247,.1)}
.bundle-disc-badge{display:inline-block;background:rgba(74,222,128,.12);border:1px solid rgba(74,222,128,.25);color:rgba(74,222,128,.9);font-size:10px;font-weight:700;padding:2px 8px;border-radius:5px}
/* ── م3: Confirm Delete ── */
.confirm-del-ov{position:fixed;inset:0;background:rgba(0,0,0,.93);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);z-index:3000;display:none;align-items:center;justify-content:center;padding:20px}
.confirm-del-ov.on{display:flex}
.confirm-del-box{background:rgba(12,4,22,.98);border:1px solid rgba(239,68,68,.35);border-radius:16px;padding:22px;max-width:340px;width:100%;text-align:center}
.confirm-del-title{font-size:14px;color:rgba(252,165,165,.9);font-weight:600;margin-bottom:8px}
.confirm-del-meta{font-size:11px;color:var(--mu);margin-bottom:16px;line-height:1.6;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.confirm-del-input{width:100%;background:rgba(255,255,255,.04);border:1px solid rgba(239,68,68,.25);border-radius:8px;color:rgba(252,165,165,.8);font-family:inherit;font-size:13px;padding:10px;text-align:center;outline:none;margin-bottom:12px;transition:border-color .2s;direction:rtl}
.confirm-del-input:focus{border-color:rgba(239,68,68,.5)}
.confirm-del-hold{display:flex;align-items:center;justify-content:center;gap:8px;font-size:10px;color:var(--mu);margin-bottom:12px}
.confirm-del-hold-bar{width:100px;height:3px;background:rgba(255,255,255,.08);border-radius:2px;overflow:hidden}
.confirm-del-hold-fill{height:100%;background:rgba(239,68,68,.7);border-radius:2px;width:0;transition:none}
.confirm-del-btns{display:flex;gap:8px}
.confirm-del-cancel{flex:1;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);color:var(--dim);border-radius:9px;padding:10px;cursor:pointer;font-size:12px;font-family:inherit;-webkit-tap-highlight-color:transparent;min-height:42px}
.confirm-del-ok{flex:1;background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);color:rgba(252,165,165,.9);border-radius:9px;padding:10px;cursor:pointer;font-size:12px;font-family:inherit;-webkit-tap-highlight-color:transparent;min-height:42px;transition:background .2s}
.confirm-del-ok:not(:disabled):hover{background:rgba(239,68,68,.28)}
.confirm-del-ok:disabled{opacity:.4;cursor:not-allowed}
/* ── م8: Order Filters ── */
.ord-filter-bar{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.ord-filter-inp{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:8px;color:var(--tx);font-family:inherit;font-size:11px;padding:7px 10px;outline:none;transition:border-color .2s;min-height:38px;-webkit-appearance:none;flex:1;min-width:90px}
.ord-filter-inp:focus{border-color:rgba(168,85,247,.4)}
.ord-filter-inp option{background:#111}
/* ── م10: Wilaya Groups ── */
.wilaya-group{border:1px solid rgba(168,85,247,.12);border-radius:10px;margin-bottom:8px;overflow:hidden}
.wilaya-group-hdr{display:flex;justify-content:space-between;align-items:center;padding:10px 13px;cursor:pointer;background:rgba(168,85,247,.04);-webkit-tap-highlight-color:transparent;min-height:44px;user-select:none}
.wilaya-group-title{font-size:12px;color:rgba(192,132,252,.8);font-weight:600}
.wilaya-group-meta{font-size:10px;color:var(--mu)}
.wilaya-group-body{display:none;padding:8px}
.wilaya-group-body.on{display:block}
/* ── م9: Internal Notes ── */
.note-ta{width:100%;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:8px;color:var(--tx);font-family:inherit;font-size:11px;padding:8px 10px;outline:none;resize:vertical;min-height:65px;transition:border-color .2s}
.note-ta:focus{border-color:rgba(168,85,247,.3)}
.note-saved-indicator{font-size:10px;color:rgba(74,222,128,.6);margin-top:4px;display:none}
/* ── م13: Bulk ── */
.bulk-bar{display:none;background:rgba(109,40,217,.1);border:1px solid rgba(168,85,247,.2);border-radius:10px;padding:10px 13px;margin-bottom:12px;flex-wrap:wrap;gap:8px;align-items:center}
.bulk-bar.on{display:flex}
/* ── م43: Drag & Drop ── */
.aprd-row[draggable=true]{cursor:grab}
.aprd-row.drag-over{background:rgba(168,85,247,.08)!important;border-color:rgba(168,85,247,.35)!important;outline:2px dashed rgba(168,85,247,.35)}
.aprd-row.dragging{opacity:.38}
/* ── م25: Stock ── */
.stock-row{display:grid;grid-template-columns:auto 1fr auto auto;gap:8px;align-items:center;padding:8px 10px;border:1px solid rgba(255,255,255,.06);border-radius:8px;margin-bottom:5px;font-size:10px}
/* ── م12: Audit Trail ── */
.audit-row{display:flex;gap:8px;align-items:flex-start;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:10px;color:var(--mu);flex-wrap:wrap}
.audit-ts{color:rgba(168,85,247,.5);white-space:nowrap;flex-shrink:0;font-family:monospace}
.audit-type{color:rgba(251,191,36,.7);white-space:nowrap;flex-shrink:0}
/* ── Toast ── */
.toast{position:fixed;bottom:max(80px,calc(70px + var(--safe-bottom)));left:50%;transform:translateX(-50%) translateY(16px);background:rgba(15,8,28,.96);border:1px solid rgba(168,85,247,.25);border-radius:10px;padding:10px 18px;font-size:12px;color:rgba(192,132,252,.9);z-index:9998;opacity:0;transition:opacity .25s,transform .25s;pointer-events:none;white-space:nowrap;max-width:90vw;text-align:center}
.toast.on{opacity:1;transform:translateX(-50%) translateY(0)}
/* ── Admin Panel ── */
.adm-ov{position:fixed;inset:0;background:rgba(0,0,0,.97);backdrop-filter:blur(30px);-webkit-backdrop-filter:blur(30px);z-index:2000;display:none;flex-direction:column;overflow:hidden}
.adm-ov.on{display:flex}
.adm-hdr{display:flex;align-items:center;justify-content:space-between;padding:11px 16px;border-bottom:1px solid rgba(168,85,247,.15);flex-shrink:0;background:rgba(3,0,8,.96);gap:10px}
.adm-title{font-family:Georgia,serif;font-size:14px;color:rgba(192,132,252,.9);letter-spacing:3px;flex-shrink:0}
.adm-close{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);color:var(--dim);border-radius:8px;padding:7px 12px;cursor:pointer;font-size:11px;font-family:inherit;-webkit-tap-highlight-color:transparent;min-height:38px;transition:background .18s,color .18s}
.adm-close:hover{background:rgba(255,255,255,.1);color:var(--tx)}
.adm-tabs{display:flex;overflow-x:auto;scrollbar-width:none;border-bottom:1px solid rgba(168,85,247,.12);flex-shrink:0;-webkit-overflow-scrolling:touch}
.adm-tabs::-webkit-scrollbar{display:none}
.adm-tab{padding:10px 13px;font-size:10px;font-weight:600;color:var(--mu);cursor:pointer;border-bottom:2px solid transparent;border-top:none;border-left:none;border-right:none;transition:color .18s,border-color .18s,background .18s;white-space:nowrap;letter-spacing:.8px;-webkit-tap-highlight-color:transparent;min-height:40px;display:flex;align-items:center;background:none;font-family:inherit}
.adm-tab:hover{color:rgba(192,132,252,.7);background:rgba(168,85,247,.04)}
.adm-tab.on{color:rgba(192,132,252,.9);border-bottom-color:rgba(168,85,247,.7);background:rgba(168,85,247,.06)}
.adm-body{flex:1;overflow-y:auto;padding:16px;-webkit-overflow-scrolling:touch}
.adm-body::-webkit-scrollbar{width:3px}
.adm-body::-webkit-scrollbar-thumb{background:rgba(168,85,247,.2);border-radius:2px}
.adm-sec{display:none}.adm-sec.on{display:block}
.adm-sec-title{font-size:9px;color:rgba(168,85,247,.5);letter-spacing:2.5px;text-transform:uppercase;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid rgba(168,85,247,.1)}
/* ── Admin Product Rows ── */
.aprd-row{display:grid;grid-template-columns:52px 1fr auto;gap:10px;align-items:center;padding:10px 12px;border:1px solid rgba(255,255,255,.06);border-radius:10px;margin-bottom:7px;background:rgba(255,255,255,.02);transition:border-color .18s,background .18s}
.aprd-row:hover{border-color:rgba(168,85,247,.2);background:rgba(168,85,247,.03)}
.aprd-img{width:52px;height:64px;object-fit:cover;border-radius:7px;background:rgba(255,255,255,.04)}
.aprd-info{min-width:0}
.aprd-name{font-size:12px;color:rgba(255,255,255,.75);font-weight:500;margin-bottom:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.aprd-price{font-size:11px;color:rgba(168,85,247,.7)}
.aprd-meta{font-size:10px;color:var(--mu);margin-top:2px}
.aprd-acts{display:flex;gap:5px;flex-shrink:0}
/* ── Admin Buttons ── */
.aibtn{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);color:var(--dim);border-radius:7px;padding:6px 10px;cursor:pointer;font-size:11px;font-family:inherit;-webkit-tap-highlight-color:transparent;min-height:36px;min-width:36px;display:flex;align-items:center;justify-content:center;transition:background .18s,border-color .18s,color .18s;white-space:nowrap}
.aibtn:hover{background:rgba(168,85,247,.12);border-color:rgba(168,85,247,.3);color:rgba(192,132,252,.8)}
.aibtn.on{background:rgba(168,85,247,.15);border-color:rgba(168,85,247,.4);color:rgba(192,132,252,.9)}
.aibtn.del:hover{background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.3);color:rgba(252,165,165,.8)}
/* ── Admin Order Rows ── */
.ord-row{border:1px solid rgba(255,255,255,.07);border-radius:12px;margin-bottom:8px;overflow:hidden;background:rgba(255,255,255,.015)}
.ord-row.repeated{border-color:rgba(239,68,68,.25);background:rgba(239,68,68,.03)}
.ord-hdr{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center;padding:10px 13px;cursor:pointer;-webkit-tap-highlight-color:transparent;min-height:52px;user-select:none}
.ord-id{font-size:10px;color:var(--mu);font-family:monospace;margin-bottom:2px}
.ord-name{font-size:13px;color:rgba(255,255,255,.78);font-weight:500}
.ord-meta{font-size:10px;color:var(--mu);margin-top:2px}
.ord-badge{display:inline-block;padding:2px 9px;border-radius:12px;font-size:9px;font-weight:700;white-space:nowrap;flex-shrink:0}
.ord-body{display:none;padding:12px 13px;border-top:1px solid rgba(255,255,255,.06)}
.ord-body.on{display:block}
.ord-det{font-size:11px;color:rgba(255,255,255,.55);line-height:2;margin-bottom:10px}
.ord-acts{display:flex;gap:6px;flex-wrap:wrap;align-items:flex-start}
.ord-sel{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.12);color:rgba(255,255,255,.65);border-radius:8px;padding:7px 10px;font-size:11px;cursor:pointer;font-family:inherit;-webkit-tap-highlight-color:transparent;min-height:40px;-webkit-appearance:none}
/* ── Admin Form Fields ── */
.af{margin-bottom:12px}
.af label{display:block;font-size:10px;font-weight:500;color:rgba(168,85,247,.75);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:5px}
.ainp{width:100%;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:9px;color:rgba(255,255,255,.88);font-family:inherit;font-size:12px;padding:9px 12px;outline:none;transition:border-color .2s,background .2s,box-shadow .2s;-webkit-appearance:none;min-height:40px}
.ainp::placeholder{color:rgba(255,255,255,.25)}
.ainp:focus{border-color:rgba(168,85,247,.4);background:rgba(255,255,255,.06);box-shadow:0 0 0 3px rgba(168,85,247,.08)}
.ainp option{background:#111}
.adm-row2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.price-hint{font-size:10px;color:var(--mu);margin-top:4px}
/* ── Drop Zone ── */
.drop-zone{border:2px dashed rgba(168,85,247,.25);border-radius:12px;padding:22px;text-align:center;cursor:pointer;font-size:11px;color:var(--mu);-webkit-tap-highlight-color:transparent;min-height:80px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:6px;transition:border-color .2s,background .2s}
.drop-zone:hover,.drop-zone.drag{border-color:rgba(168,85,247,.5);background:rgba(168,85,247,.04)}
.img-prev{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.img-prev-item{position:relative;width:68px;height:85px}
.img-prev-item img{width:100%;height:100%;object-fit:cover;border-radius:7px;border:1px solid rgba(168,85,247,.2)}
.img-del{position:absolute;top:-5px;right:-5px;background:#ef4444;border:none;color:#fff;width:18px;height:18px;border-radius:50%;cursor:pointer;font-size:10px;display:flex;align-items:center;justify-content:center;-webkit-tap-highlight-color:transparent}
/* ── KPI Cards ── */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:9px;margin-bottom:18px}
.kpi-card{background:rgba(255,255,255,.03);border:1px solid rgba(168,85,247,.1);border-radius:12px;padding:13px}
.kpi-label{font-size:9px;color:var(--mu);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:5px}
.kpi-val{font-family:Georgia,serif;font-size:19px;color:rgba(192,132,252,.9);font-weight:700;line-height:1.2}
.kpi-sub{font-size:9px;color:var(--mu);margin-top:3px}
.kpi-good{color:rgba(74,222,128,.8)!important}
.kpi-bad{color:rgba(252,165,165,.8)!important}
/* ── Charts (م15) ── */
.chart-wrap{background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:14px;margin-bottom:14px;overflow:hidden}
.chart-title{font-size:9px;color:var(--mu);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:10px}
/* ── Device bars (م2) ── */
.dev-bar{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.dev-bar-label{color:var(--mu);min-width:70px;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dev-bar-fill{height:5px;border-radius:3px;background:linear-gradient(90deg,#a855f7,#c084fc);transition:width .6s ease;flex-shrink:0}
.dev-bar-val{color:rgba(192,132,252,.8);font-size:10px;margin-right:auto;flex-shrink:0}
/* ── Coupon / Flash / Bundle rows ── */
.cp-row{display:flex;gap:8px;align-items:center;padding:9px 12px;border:1px solid rgba(109,40,217,.15);border-radius:9px;margin-bottom:6px;background:rgba(109,40,217,.04);font-size:11px;flex-wrap:wrap}
.fs-row{display:flex;gap:8px;align-items:center;padding:9px 12px;border:1px solid rgba(239,68,68,.15);border-radius:9px;margin-bottom:6px;background:rgba(239,68,68,.04);font-size:11px;flex-wrap:wrap}
/* ── م44: Lang tabs ── */
.lang-tab{display:inline-flex;border:1px solid var(--b1);border-radius:7px;overflow:hidden;margin-bottom:10px}
.lang-tab-btn{padding:5px 14px;font-size:10px;cursor:pointer;background:transparent;border:none;color:var(--mu);font-family:inherit;-webkit-tap-highlight-color:transparent;min-height:32px;transition:background .15s,color .15s}
.lang-tab-btn.on{background:rgba(168,85,247,.12);color:rgba(192,132,252,.9)}
/* ── Scheduled badge ── */
.scheduled-badge{display:inline-flex;align-items:center;gap:4px;background:rgba(99,102,241,.1);border:1px solid rgba(99,102,241,.25);color:rgba(165,180,252,.8);font-size:9px;padding:2px 7px;border-radius:4px}
/* ── Footer ── */
.footer{text-align:center;padding:28px 16px calc(80px + var(--safe-bottom));color:var(--mu);font-size:10px;letter-spacing:1.5px;border-top:1px solid rgba(255,255,255,.04);margin-top:16px}
.footer a{color:rgba(168,85,247,.5);text-decoration:none}
/* ── م46: Keyboard hints ── */
.kbd{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:3px;padding:1px 5px;font-family:monospace;font-size:9px}
/* ── Invoice mini ── */
.inv{background:#fafaf8;color:#111;border-radius:14px;padding:24px;max-width:440px;width:100%;font-family:inherit;animation:pop .32s cubic-bezier(.34,1.56,.64,1);max-height:92vh;overflow-y:auto;direction:rtl}
.inv-brand{font-family:Georgia,serif;font-size:32px;font-weight:900;color:#111;letter-spacing:4px;text-align:center;margin-bottom:2px}
.inv-sub{font-size:9px;color:#999;text-transform:uppercase;letter-spacing:3px;text-align:center;margin-bottom:18px}
.inv-grid{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-bottom:14px;background:#f5f5f3;border-radius:9px;padding:12px}
.inv-f small{display:block;font-size:9px;color:#999;text-transform:uppercase;letter-spacing:1px;margin-bottom:1px}
.inv-f span{font-size:12px;font-weight:600;color:#111}
.inv-item{display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid #f0f0f0;font-size:11px}
.inv-tots{background:#f9f9f7;border-radius:9px;padding:12px;margin:10px 0}
.inv-row{display:flex;justify-content:space-between;font-size:11px;margin-bottom:5px;color:#666}
.inv-final{display:flex;justify-content:space-between;align-items:center;padding-top:8px;margin-top:4px;border-top:2px solid #e0e0e0}
.inv-total{font-family:Georgia,serif;font-size:20px;font-weight:900;color:#111}
@media(max-width:600px){
  .adm-row2{grid-template-columns:1fr}
  .kpi-grid{grid-template-columns:1fr 1fr}
  .ord-filter-bar{flex-direction:column}
  .hdr-i{padding:9px 12px}
  .search-wrap{max-width:none}
}
</style>
</head>
<body>
<div class="vignette"></div>
<div class="ambient-bg"></div>
<div id="scroll-prog"></div>
${featBarHTML}
<!-- HEADER -->
<header class="hdr" id="main-hdr">
  <div class="hdr-i">
    <a class="logo" href="/" id="logo-link" aria-label="${sn}">
      <svg width="40" height="40" viewBox="0 0 42 42" fill="none" xmlns="http://www.w3.org/2000/svg">
        <ellipse cx="21" cy="21" rx="18" ry="18" fill="rgba(10,0,22,.9)" stroke="rgba(168,85,247,.35)" stroke-width="1.2"/>
        <ellipse cx="21" cy="21" rx="10" ry="10" fill="rgba(88,28,135,.22)" stroke="rgba(168,85,247,.2)" stroke-width="1"/>
        <ellipse cx="21" cy="21" rx="5.5" ry="5.5" fill="rgba(109,40,217,.45)"/>
        <text x="21" y="25" text-anchor="middle" font-family="Georgia,serif" font-size="6" font-weight="900" fill="rgba(192,132,252,.9)" letter-spacing="1.5">WOW</text>
      </svg>
    </a>
    <div class="search-wrap">
      <input class="search-inp" id="search-inp" type="search" placeholder="بحث..." autocomplete="off" aria-label="بحث" inputmode="search">
      <span class="search-ico" aria-hidden="true">&#9906;</span>
    </div>
    <div class="hdr-r">
      <button class="cart-btn" id="cart-btn" aria-label="السلة">
        <span>السلة</span>
        <span class="cbdg" id="cart-count" aria-live="polite">0</span>
      </button>
      <button class="adm-btn" id="adm-btn" aria-label="لوحة التحكم">&#9881;</button>
    </div>
  </div>
</header>
<!-- HERO -->
<div class="hero-bg" id="hero-bg">
  <div class="hero-bg-fallback"></div>
  <div class="hero-bg-overlay"></div>
</div>
<!-- FILTERS -->
<div class="flt-wrap" id="flt-wrap" role="toolbar" aria-label="فلاتر">
  <button class="flt-btn on" onclick="WOW.flt('all',this)">الكل</button>
  <button class="flt-btn" onclick="WOW.flt('new',this)">جديد</button>
  <button class="flt-btn" onclick="WOW.flt('top',this)">الاكثر مبيعا</button>
  <button class="flt-btn" onclick="WOW.flt('shirts',this)">قمصان</button>
  <button class="flt-btn" onclick="WOW.flt('pants',this)">بنطلونات</button>
  <button class="flt-btn" onclick="WOW.flt('shorts',this)">شورتات</button>
  <button class="flt-btn" onclick="WOW.flt('hats',this)">قبعات</button>
  <button class="flt-btn" onclick="WOW.flt('accessories',this)">اكسسوار</button>
</div>
<!-- MAIN GRID -->
<main id="main-content">
  <div class="grid" id="prod-grid">
    ${[...Array(6)].map(()=>`<div class="skel-card"><div class="skel skel-img"></div><div class="skel-body"><div class="skel skel-line" style="width:60%"></div><div class="skel skel-price"></div><div class="skel skel-btn"></div></div></div>`).join("")}
  </div>
  <div id="bundles-section" style="max-width:1200px;margin:0 auto;padding:0 16px 16px;display:none"></div>
  <div id="testimonials-section" style="max-width:1200px;margin:0 auto;padding:0 16px 24px;display:none"></div>
</main>
<!-- FOOTER -->
<footer class="footer">
  <div style="margin-bottom:8px;display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
    <a href="/about">عن المتجر</a>
    <a href="https://wa.me/${wa}" target="_blank" rel="noopener">واتساب</a>
    <a href="https://instagram.com/${ig}" target="_blank" rel="noopener">انستغرام</a>
    <a href="/stories">قصص النجاح</a>
    <a href="#" onclick="document.getElementById('track-ov').classList.add('on');return false">تتبع طلبيتك</a>
    ${s.showFaq!==false?`<a href="#" onclick="WOW._openFaq();return false">الاسئلة الشائعة</a>`:""}
    ${s.showRefundPolicy!==false?`<a href="#" onclick="WOW._openRefund();return false">سياسة الارجاع</a>`:""}
  </div>
  <div id="trust-badges-footer"></div>
  <div style="margin-top:10px">${sn} &copy; ${new Date().getFullYear()}</div>
</footer>
<!-- OVERLAY -->
<div class="ov" id="cart-ov" onclick="WOW.closeCart()"></div>
<!-- CART SIDEBAR -->
<aside class="cart-sb" id="cart-sb" role="complementary" aria-label="السلة">
  <div class="cart-hdr">
    <span class="cart-title">CART</span>
    <button class="close-btn" onclick="WOW.closeCart()" aria-label="اغلاق">&#10005;</button>
  </div>
  <div class="cart-items" id="cart-items" role="list"></div>
  <div class="cart-ft" id="cart-ft" style="display:none">
    <div class="cart-tot">
      <span class="cart-tot-l">TOTAL</span>
      <span class="cart-tot-v" id="cart-total-val">0 دج</span>
    </div>
    <button class="btn-main" id="chk-btn" onclick="WOW.openCheckout()">اتمام الطلب</button>
  </div>
</aside>
<!-- PRODUCT MODAL -->
<div class="mod-ov" id="mod-ov" role="dialog" aria-modal="true">
  <div class="mod" id="mod-box">
    <div class="mod-title">
      <span id="mod-cat" style="font-size:9px;color:rgba(168,85,247,.45);letter-spacing:2px;text-transform:uppercase"></span>
      <button class="close-btn" onclick="WOW.closeMod()" aria-label="اغلاق">&#10005;</button>
    </div>
    <div class="gal">
      <div class="gal-main"><img id="pm-main-img" src="" alt="" loading="eager"></div>
      <div class="gal-thumbs" id="pm-thumbs"></div>
    </div>
    <div id="mod-rating" style="margin-bottom:6px"></div>
    <h2 id="mod-name" style="font-family:Georgia,serif;font-size:18px;color:rgba(255,255,255,.9);margin-bottom:6px"></h2>
    <div class="price-wrap" style="margin-bottom:10px">
      <span id="mod-price" class="card-price"></span>
      <span id="mod-old-price" class="card-price-old"></span>
      <span id="mod-disc-badge" class="disc-badge" style="display:none"></span>
    </div>
    <p id="mod-desc" style="font-size:12px;color:var(--dim);line-height:1.7;margin-bottom:14px"></p>
    <div id="mod-sizes" style="margin-bottom:12px"></div>
    <div id="mod-colors" style="margin-bottom:12px"></div>
    <div id="mod-variants" style="margin-bottom:12px"></div>
    <div id="mod-scarcity" style="margin-bottom:10px"></div>
    <div style="display:flex;gap:8px;margin-bottom:12px;align-items:center">
      <div style="display:flex;border:1px solid rgba(255,255,255,.1);border-radius:8px;overflow:hidden">
        <button id="qty-dec" style="background:rgba(255,255,255,.05);border:none;color:var(--dim);width:36px;height:40px;cursor:pointer;font-size:18px;-webkit-tap-highlight-color:transparent;touch-action:manipulation;display:flex;align-items:center;justify-content:center" aria-label="تقليل">-</button>
        <input id="mod-qty" type="number" value="1" min="1" max="99" style="width:44px;background:none;border:none;color:var(--tx);font-size:13px;text-align:center;font-family:inherit;padding:0" aria-label="الكمية">
        <button id="qty-inc" style="background:rgba(255,255,255,.05);border:none;color:var(--dim);width:36px;height:40px;cursor:pointer;font-size:18px;-webkit-tap-highlight-color:transparent;touch-action:manipulation;display:flex;align-items:center;justify-content:center" aria-label="زيادة">+</button>
      </div>
      <button class="btn-main" id="mod-add-btn" style="flex:1" onclick="WOW.confirmAdd()">اضافة للسلة</button>
    </div>
    <div id="mod-waitlist"></div>
    <div id="mod-review-section" style="margin-top:14px"></div>
    <div style="display:flex;gap:7px;margin-top:12px">
      <button class="aibtn" style="flex:1" onclick="WOW._showQR()">QR</button>
      <button class="aibtn" style="flex:1" onclick="WOW._copyProdLink()">نسخ الرابط</button>
    </div>
  </div>
</div>
<!-- SIZE GUIDE MODAL -->
<div class="mod-ov" id="size-mod-ov" role="dialog" aria-modal="true">
  <div class="mod" style="max-width:440px">
    <div class="mod-title">
      <span>دليل المقاسات</span>
      <button class="close-btn" onclick="WOW.openSizeMod(false)" aria-label="اغلاق">&#10005;</button>
    </div>
    <div id="size-guide-grid" style="display:grid;grid-template-columns:repeat(4,1fr);gap:6px"></div>
  </div>
</div>
<!-- CHECKOUT MODAL -->
<div class="mod-ov" id="chk-ov" role="dialog" aria-modal="true">
  <div class="mod" id="chk-box">
    <div class="mod-title">
      <span>اتمام الطلب</span>
      <button class="close-btn" onclick="WOW.closeChk()" aria-label="اغلاق">&#10005;</button>
    </div>
    <div class="stepper" id="chk-stepper" role="progressbar">
      <div class="step-item active" id="step0"><div class="step-dot">1</div><div class="step-lbl">معلومات</div></div>
      <div class="step-item" id="step1"><div class="step-dot">2</div><div class="step-lbl">العنوان</div></div>
      <div class="step-item" id="step2"><div class="step-dot">3</div><div class="step-lbl">الدفع</div></div>
      <div class="step-item" id="step3"><div class="step-dot">4</div><div class="step-lbl">تاكيد</div></div>
    </div>
    <div class="chk-step active" id="chk-s0">
      <div class="fl"><label>الاسم الكامل</label><input class="inp" id="b-name" placeholder="الاسم الكامل" autocomplete="name" inputmode="text"></div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:9px">
        <div class="fl"><label>الهاتف 1</label><input class="inp" id="b-phone1" type="tel" placeholder="05xxxxxxxx" autocomplete="tel" inputmode="tel"></div>
        <div class="fl"><label>الهاتف 2</label><input class="inp" id="b-phone2" type="tel" placeholder="05xxxxxxxx" autocomplete="tel" inputmode="tel"></div>
      </div>
      <div class="fl"><label>البريد (اختياري)</label><input class="inp" id="b-email" type="email" placeholder="email@..." autocomplete="email" inputmode="email"></div>
      <div class="fl"><label>كوبون الخصم</label>
        <div style="display:flex;gap:6px">
          <input class="inp" id="coupon-inp" placeholder="كود الخصم" autocomplete="off" style="flex:1">
          <button class="btn-main" style="width:auto;padding:9px 14px;flex-shrink:0" onclick="WOW._applyCoupon()">تطبيق</button>
        </div>
        <div id="coupon-msg" style="font-size:10px;margin-top:4px;min-height:16px"></div>
      </div>
      <div class="step-nav"><button class="btn-main" onclick="WOW.chkNext(0)">التالي</button></div>
    </div>
    <div class="chk-step" id="chk-s1">
      <div class="fl"><label>الولاية</label>
        <select class="inp" id="b-wilaya" onchange="WOW.updPreview()">
          <option value="">اختر الولاية</option>${wilayaOpts}
        </select>
      </div>
      <div class="fl"><label>البلدية</label><input class="inp" id="b-commune" placeholder="البلدية" oninput="WOW.updPreview()" autocomplete="address-level2"></div>
      <div class="fl"><label>نوع التوصيل</label>
        <select class="inp" id="b-dlbl" onchange="WOW.updPreview()">
          <option value="Stop Desk">Stop Desk</option>
          <option value="التوصيل للمنزل">توصيل للمنزل</option>
        </select>
      </div>
      <div class="op" id="ord-preview" style="display:none">
        <div class="op-row"><span class="op-l">المنتجات</span><span class="op-v" id="op-sub">-</span></div>
        <div class="op-row" id="op-disc-row" style="display:none;color:rgba(74,222,128,.8)"><span class="op-l">خصم</span><span class="op-v" id="op-disc">-</span></div>
        <div class="op-row"><span class="op-l">التوصيل</span><span class="op-v" id="op-fee">-</span></div>
        <div class="op-tot"><span class="op-tl">TOTAL</span><span class="op-tv" id="op-total">-</span></div>
      </div>
      <div class="step-nav">
        <button class="btn-back" onclick="WOW.chkPrev(1)">رجوع</button>
        <button class="btn-main" onclick="WOW.chkNext(1)">التالي</button>
      </div>
    </div>
    <div class="chk-step" id="chk-s2">
      <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:14px">
        <label class="pay-opt">
          <input type="radio" name="pay-method" value="cod" checked onchange="WOW.updPreview()">
          <div class="pay-opt-body">
            <div class="pay-opt-title">الدفع عند الاستلام</div>
            <div class="pay-opt-sub">ادفع عند استلام طلبك</div>
          </div>
        </label>
        <label class="pay-opt">
          <input type="radio" name="pay-method" value="ccp" onchange="WOW.updPreview()">
          <div class="pay-opt-body">
            <div class="pay-opt-title">CCP مسبق <span style="background:rgba(74,222,128,.12);border:1px solid rgba(74,222,128,.25);color:rgba(74,222,128,.8);font-size:9px;padding:1px 6px;border-radius:4px">وفر 50 دج</span></div>
            <div class="pay-opt-sub">دفع مسبق — ${wa}</div>
          </div>
        </label>
      </div>
      <div id="ccp-ref-field" style="display:none">
        <div class="fl"><label>رقم وصل CCP</label><input class="inp" id="b-ccp-ref" placeholder="رقم الوصل" autocomplete="off"></div>
      </div>
      <div class="fl"><label>ملاحظة (اختياري)</label><textarea class="inp" id="b-note" placeholder="ملاحظة للبائع..." rows="2" style="resize:vertical;min-height:70px"></textarea></div>
      <div class="step-nav">
        <button class="btn-back" onclick="WOW.chkPrev(2)">رجوع</button>
        <button class="btn-main" onclick="WOW.chkNext(2)">التالي</button>
      </div>
    </div>
    <div class="chk-step" id="chk-s3">
      <div id="chk-summary" class="op" style="margin-bottom:16px"></div>
      <button class="btn-main" id="submit-btn" onclick="WOW.submitOrder()">تاكيد الطلب</button>
    </div>
  </div>
</div>
<!-- INVOICE MODAL -->
<div class="mod-ov" id="inv-ov" role="dialog" aria-modal="true">
  <div class="inv" id="inv-box"></div>
</div>
<!-- TRACK MODAL -->
<div class="mod-ov" id="track-ov" role="dialog" aria-modal="true">
  <div class="mod" style="max-width:400px">
    <div class="mod-title">
      <span>تتبع الطلبية</span>
      <button class="close-btn" onclick="document.getElementById('track-ov').classList.remove('on')" aria-label="اغلاق">&#10005;</button>
    </div>
    <div class="fl"><label>رقم الطلبية او الهاتف</label><input class="inp" id="track-inp" placeholder="WOW-xxxxxxx" inputmode="text" autocomplete="off"></div>
    <button class="btn-main" onclick="WOW.doTrack()">تتبع</button>
    <div id="track-result" style="margin-top:14px"></div>
  </div>
</div>
<!-- QR MODAL -->
<div class="mod-ov" id="qr-ov" role="dialog" aria-modal="true">
  <div class="mod" style="max-width:300px">
    <div class="mod-title">
      <span>QR المنتج</span>
      <button class="close-btn" onclick="document.getElementById('qr-ov').classList.remove('on')" aria-label="اغلاق">&#10005;</button>
    </div>
    <div style="text-align:center;padding:12px 0"><div class="qr-wrap" id="qr-content"></div></div>
    <button class="btn-main" style="margin-top:10px" onclick="WOW._copyProdLink()">نسخ الرابط</button>
  </div>
</div>
<!-- REVIEW MODAL -->
<div class="mod-ov" id="review-mod-ov" role="dialog" aria-modal="true">
  <div class="mod" style="max-width:400px">
    <div class="mod-title">
      <span>تقييم المنتج</span>
      <button class="close-btn" onclick="document.getElementById('review-mod-ov').classList.remove('on')" aria-label="اغلاق">&#10005;</button>
    </div>
    <div class="fl"><label>تقييمك</label><div id="rv-stars" style="display:flex;gap:6px;margin-bottom:10px"></div></div>
    <div class="fl"><label>الاسم</label><input class="inp" id="rv-name" placeholder="اسمك" autocomplete="name"></div>
    <div class="fl"><label>الهاتف (للتحقق)</label><input class="inp" id="rv-phone" type="tel" placeholder="05xxxxxxxx" inputmode="tel"></div>
    <div class="fl"><label>تعليق (اختياري)</label><textarea class="inp" id="rv-body" rows="3" style="resize:vertical;min-height:70px" placeholder="رأيك..."></textarea></div>
    <input type="hidden" id="rv-prod-id">
    <button class="btn-main" onclick="WOW._submitReview()">ارسال التقييم</button>
  </div>
</div>
<!-- FAQ MODAL -->
<div class="mod-ov" id="faq-ov" role="dialog" aria-modal="true">
  <div class="mod">
    <div class="mod-title">
      <span>الاسئلة الشائعة</span>
      <button class="close-btn" onclick="document.getElementById('faq-ov').classList.remove('on')" aria-label="اغلاق">&#10005;</button>
    </div>
    <div id="faq-content"></div>
  </div>
</div>
<!-- REFUND MODAL -->
<div class="mod-ov" id="refund-ov" role="dialog" aria-modal="true">
  <div class="mod">
    <div class="mod-title">
      <span>سياسة الارجاع</span>
      <button class="close-btn" onclick="document.getElementById('refund-ov').classList.remove('on')" aria-label="اغلاق">&#10005;</button>
    </div>
    <div id="refund-content" style="font-size:12px;color:var(--dim);line-height:1.9"></div>
  </div>
</div>
<!-- ADMIN LOGIN MODAL -->
<div class="mod-ov" id="adm-login-ov" role="dialog" aria-modal="true">
  <div class="mod" style="max-width:340px">
    <div class="mod-title"><span style="letter-spacing:3px">ADMIN</span></div>
    <div class="fl"><label>كلمة المرور</label>
      <input class="inp" id="adm-pass" type="password" placeholder="********" autocomplete="current-password">
    </div>
    <button class="btn-main" id="adm-login-btn" onclick="WOW.doLogin()">دخول</button>
    <div id="adm-login-msg" style="font-size:11px;color:rgba(252,165,165,.7);margin-top:8px;text-align:center;min-height:18px"></div>
  </div>
</div>
<!-- م3: CONFIRM DELETE -->
<div class="confirm-del-ov" id="confirm-del-ov" role="dialog" aria-modal="true">
  <div class="confirm-del-box">
    <div class="confirm-del-title" id="cd-title">تاكيد الحذف</div>
    <div class="confirm-del-meta" id="cd-meta"></div>
    <div class="confirm-del-hold" id="cd-hold-wrap">
      <span style="font-size:10px">اضغط مطولاً للحذف</span>
      <div class="confirm-del-hold-bar"><div class="confirm-del-hold-fill" id="cd-hold-fill"></div></div>
    </div>
    <input class="confirm-del-input" id="cd-input" placeholder='اكتب "حذف" للتاكيد' autocomplete="off" autocorrect="off">
    <div class="confirm-del-btns">
      <button class="confirm-del-cancel" id="cd-cancel-btn">الغاء</button>
      <button class="confirm-del-ok" id="cd-ok-btn" disabled>حذف</button>
    </div>
  </div>
</div>
<!-- ADMIN PANEL -->
<div class="adm-ov" id="adm-ov" role="dialog" aria-modal="true" aria-label="لوحة التحكم">
  <div class="adm-hdr">
    <span class="adm-title">ADMIN</span>
    <div style="display:flex;gap:6px;align-items:center">
      <span style="font-size:9px;color:rgba(255,255,255,.2)"><span class="kbd">F</span> ملء الشاشة</span>
      <button class="aibtn" id="fullscreen-btn" onclick="WOW._toggleFullscreen()" style="min-width:36px;min-height:36px" title="ملء الشاشة">[ ]</button>
      <button class="adm-close" id="adm-close-btn">&#10005; اغلاق</button>
    </div>
  </div>
  <div class="adm-tabs" role="tablist">
    <button class="adm-tab on" id="tab-dash"      onclick="WOW.aTab('dash',this)"      role="tab">الرئيسية</button>
    <button class="adm-tab"    id="tab-orders"    onclick="WOW.aTab('orders',this)"    role="tab">الطلبيات</button>
    <button class="adm-tab"    id="tab-products"  onclick="WOW.aTab('products',this)"  role="tab">المنتجات</button>
    <button class="adm-tab"    id="tab-addprod"   onclick="WOW.aTab('addprod',this)"   role="tab">اضافة</button>
    <button class="adm-tab"    id="tab-coupons"   onclick="WOW.aTab('coupons',this)"   role="tab">كوبونات</button>
    <button class="adm-tab"    id="tab-archive"   onclick="WOW.aTab('archive',this)"   role="tab">الارشيف</button>
    <button class="adm-tab"    id="tab-analytics" onclick="WOW.aTab('analytics',this)" role="tab">الاحصائيات</button>
    <button class="adm-tab"    id="tab-visitors"  onclick="WOW.aTab('visitors',this)"  role="tab">الزوار</button>
    <button class="adm-tab"    id="tab-stock"     onclick="WOW.aTab('stock',this)"     role="tab">المخزون</button>
    <button class="adm-tab"    id="tab-reviews"   onclick="WOW.aTab('reviews',this)"   role="tab">التقييمات</button>
    <button class="adm-tab"    id="tab-loyalty"   onclick="WOW.aTab('loyalty',this)"   role="tab">الولاء</button>
    <button class="adm-tab"    id="tab-settings"  onclick="WOW.aTab('settings',this)"  role="tab">الاعدادات</button>
    <button class="adm-tab"    id="tab-activity"  onclick="WOW.aTab('activity',this)"  role="tab">السجل</button>
  </div>
  <div class="adm-body" id="adm-body">
    <!-- DASH -->
    <div class="adm-sec on" id="sec-dash">
      <div class="adm-sec-title">لوحة القيادة</div>
      <div class="kpi-grid" id="dash-kpis"></div>
      <div class="chart-wrap"><div class="chart-title">المبيعات — 14 يوم</div><svg id="sales-chart" width="100%" height="110" style="overflow:visible"></svg></div>
      <div id="alert-low-stock" style="display:none;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:10px;padding:12px;margin-bottom:14px">
        <strong style="display:block;margin-bottom:6px;font-size:10px;color:rgba(252,165,165,.8);letter-spacing:1px">مخزون منخفض</strong>
        <div id="alert-low-stock-list" style="font-size:11px;color:rgba(252,165,165,.7)"></div>
      </div>
      <div id="alert-duplicates" style="display:none;background:rgba(251,191,36,.07);border:1px solid rgba(251,191,36,.2);border-radius:10px;padding:12px;margin-bottom:14px">
        <strong style="display:block;margin-bottom:6px;font-size:10px;color:rgba(253,224,71,.8);letter-spacing:1px">طلبيات مكررة</strong>
        <div id="alert-dup-list" style="font-size:11px;color:rgba(253,224,71,.7)"></div>
      </div>
      <div style="display:flex;gap:7px;flex-wrap:wrap;margin-bottom:14px">
        <button class="aibtn" id="orders-refresh-btn">تحديث</button>
        <button class="aibtn" id="push-btn">الاشعارات</button>
        <button class="aibtn" id="goto-addprod">اضافة منتج</button>
        <button class="aibtn" onclick="WOW.aTab('analytics',null)">الاحصائيات</button>
        <a href="/api-docs" target="_blank" style="text-decoration:none"><button class="aibtn">API Docs</button></a>
      </div>
      <div class="chart-wrap"><div class="chart-title">KV Storage</div><div id="kv-stats-bar"></div></div>
    </div>
    <!-- ORDERS -->
    <div class="adm-sec" id="sec-orders">
      <div class="adm-sec-title">الطلبيات</div>
      <div class="ord-filter-bar">
        <input class="ord-filter-inp" id="ord-search"         placeholder="بحث: اسم، هاتف، رقم..." oninput="WOW._filterOrders()">
        <select class="ord-filter-inp" id="ord-flt-status"    onchange="WOW._filterOrders()">
          <option value="">كل الحالات</option>
          <option value="processing">قيد المعالجة</option>
          <option value="shipped">تم الشحن</option>
          <option value="delivered">تم التوصيل</option>
          <option value="returned">مرتجعة</option>
        </select>
        <select class="ord-filter-inp" id="ord-flt-wilaya"    onchange="WOW._filterOrders()">
          <option value="">كل الولايات</option>${wilayaOpts}
        </select>
        <select class="ord-filter-inp" id="ord-flt-confirmed" onchange="WOW._filterOrders()">
          <option value="">الكل</option>
          <option value="1">مؤكدة</option>
          <option value="0">غير مؤكدة</option>
        </select>
      </div>
      <div class="bulk-bar" id="bulk-bar">
        <span id="bulk-count" style="font-size:11px;color:var(--mu)">0 محدد</span>
        <button class="aibtn" onclick="WOW._bulkPrint()">طباعة</button>
        <button class="aibtn" onclick="WOW._bulkConfirm(true)">تاكيد الكل</button>
        <button class="aibtn" onclick="WOW._bulkStatus('shipped')">شحن الكل</button>
        <button class="aibtn" style="margin-right:auto" onclick="WOW._clearBulk()">الغاء</button>
      </div>
      <div style="display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap">
        <button class="aibtn" onclick="WOW._groupOrders()">تجميع بالولاية</button>
        <button class="aibtn" onclick="WOW._exportCSV()">تصدير CSV</button>
        <button class="aibtn" id="orders-clear-btn" style="color:rgba(252,165,165,.5)">مسح الكل</button>
      </div>
      <div id="csv-col-chooser" style="display:none;background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.07);border-radius:9px;padding:10px;margin-bottom:10px">
        <div style="font-size:10px;color:var(--mu);margin-bottom:8px;letter-spacing:1px">اختر الاعمدة</div>
        <div style="display:flex;flex-wrap:wrap;gap:8px" id="csv-cols"></div>
        <button class="aibtn" style="margin-top:8px" onclick="WOW._doExportCSV()">تصدير</button>
      </div>
      <div id="ord-list"></div>
    </div>
    <!-- PRODUCTS -->
    <div class="adm-sec" id="sec-products">
      <div class="adm-sec-title">المنتجات <span id="prod-count-lbl" style="color:var(--mu)"></span></div>
      <div style="display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap">
        <input class="ord-filter-inp" id="aprd-search"  placeholder="بحث..." oninput="WOW._filterAdminProds()" style="flex:1">
        <select class="ord-filter-inp" id="aprd-cat-flt" onchange="WOW._filterAdminProds()">
          <option value="">كل الفئات</option>
          <option value="shirts">قمصان</option><option value="pants">بنطلونات</option>
          <option value="shorts">شورتات</option><option value="hats">قبعات</option>
          <option value="accessories">اكسسوار</option><option value="other">اخرى</option>
        </select>
        <button class="aibtn" onclick="WOW.aTab('addprod',null)">+ اضافة</button>
      </div>
      <div id="aprd-list"></div>
    </div>
    <!-- ADD/EDIT PRODUCT -->
    <div class="adm-sec" id="sec-addprod">
      <div class="adm-sec-title" id="addprod-title">اضافة منتج جديد</div>
      <input type="hidden" id="edit-id">
      <div class="lang-tab">
        <button class="lang-tab-btn on" id="lt-ar" onclick="WOW._switchLang('ar',this)">عربي</button>
        <button class="lang-tab-btn"    id="lt-en" onclick="WOW._switchLang('en',this)">EN</button>
        <button class="lang-tab-btn"    id="lt-fr" onclick="WOW._switchLang('fr',this)">FR</button>
      </div>
      <div class="af"><label>اسم المنتج</label><input class="ainp" id="p-name" placeholder="اسم المنتج"></div>
      <div class="af" id="p-name-en-wrap" style="display:none"><label>Product Name (EN)</label><input class="ainp" id="p-name-en" placeholder="Product name"></div>
      <div class="af" id="p-name-fr-wrap" style="display:none"><label>Nom du Produit (FR)</label><input class="ainp" id="p-name-fr" placeholder="Nom..."></div>
      <div class="adm-row2">
        <div class="af"><label>السعر (دج)</label><input class="ainp" id="p-price" type="number" min="0" placeholder="0" oninput="WOW.calcDisc()"></div>
        <div class="af"><label>الخصم %</label><input class="ainp" id="p-disc" type="number" min="0" max="90" placeholder="0" oninput="WOW.calcDisc()"></div>
      </div>
      <div id="disc-preview" class="price-hint" style="display:none"></div>
      <div class="adm-row2">
        <div class="af"><label>سعر التكلفة (دج)</label><input class="ainp" id="p-cost" type="number" min="0" placeholder="0"></div>
        <div class="af"><label>الفئة</label>
          <select class="ainp" id="p-cat">
            <option value="other">اخرى</option><option value="shirts">قمصان</option>
            <option value="pants">بنطلونات</option><option value="shorts">شورتات</option>
            <option value="hats">قبعات</option><option value="accessories">اكسسوار</option>
          </select>
        </div>
      </div>
      <div class="af"><label>الوصف</label><textarea class="ainp" id="p-desc" rows="3" style="resize:vertical;min-height:80px" placeholder="وصف المنتج"></textarea></div>
      <div class="af" id="p-desc-en-wrap" style="display:none"><label>Description (EN)</label><textarea class="ainp" id="p-desc-en" rows="2" style="resize:vertical" placeholder="Description..."></textarea></div>
      <div class="af" id="p-desc-fr-wrap" style="display:none"><label>Description (FR)</label><textarea class="ainp" id="p-desc-fr" rows="2" style="resize:vertical" placeholder="Description..."></textarea></div>
      <div class="adm-row2">
        <div class="af"><label>الكمية (فارغ=غير محدود)</label><input class="ainp" id="p-qty" type="number" min="0" placeholder="غير محدود" inputmode="numeric"></div>
        <div class="af"><label>حد التنبيه</label><input class="ainp" id="p-alert-qty" type="number" min="0" value="5" inputmode="numeric"></div>
      </div>
      <div class="af"><label>المقاسات (افصل بفاصلة)</label><input class="ainp" id="p-sizes" placeholder="S, M, L, XL"></div>
      <div class="af"><label>الالوان (افصل بفاصلة)</label><input class="ainp" id="p-colors" placeholder="احمر, ازرق, اخضر"></div>
      <div class="af"><label>جدولة النشر (م28)</label>
        <input class="ainp" id="p-show-at" type="datetime-local">
        <div class="price-hint">فارغ = نشر فوري</div>
      </div>
      <div class="af">
        <label>صور المنتج (حتى 4)</label>
        <div class="drop-zone" id="drop-zone" role="button" tabindex="0" aria-label="رفع الصور">
          <span style="font-size:22px;color:rgba(168,85,247,.4)">+</span>
          <span>اسحب الصور او اضغط للرفع</span>
          <span style="font-size:10px;color:rgba(255,255,255,.2)">JPG, PNG, WEBP</span>
        </div>
        <input type="file" id="p-img-file" accept="image/*" multiple style="display:none" aria-hidden="true" tabindex="-1">
        <div class="img-prev" id="img-prev"></div>
      </div>
      <div style="display:flex;gap:8px;margin-top:16px;flex-wrap:wrap">
        <button class="btn-main" id="save-btn" style="flex:1">حفظ المنتج</button>
        <button class="aibtn" id="cancel-edit-btn" style="display:none">الغاء التعديل</button>
      </div>
    </div>
    <!-- COUPONS -->
    <div class="adm-sec" id="sec-coupons">
      <div class="adm-sec-title">الكوبونات</div>
      <div style="background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:14px;margin-bottom:14px">
        <div class="adm-row2">
          <div class="af"><label>الكود</label><input class="ainp" id="cp-code" placeholder="SAVE10" autocomplete="off"></div>
          <div class="af"><label>النوع</label><select class="ainp" id="cp-type"><option value="percent">نسبة %</option><option value="fixed">مبلغ ثابت</option></select></div>
        </div>
        <div class="adm-row2">
          <div class="af"><label>القيمة</label><input class="ainp" id="cp-val" type="number" min="0" placeholder="10" inputmode="decimal"></div>
          <div class="af"><label>عدد الاستخدامات (0=لا حدود)</label><input class="ainp" id="cp-maxuses" type="number" min="0" placeholder="0" inputmode="numeric"></div>
        </div>
        <div class="adm-row2">
          <div class="af"><label>انتهاء الصلاحية</label><input class="ainp" id="cp-expires" type="datetime-local"></div>
          <div class="af"><label>حد ادنى للسلة (دج)</label><input class="ainp" id="cp-minsub" type="number" min="0" placeholder="0" inputmode="numeric"></div>
        </div>
        <div class="af"><label>تقييد الولايات (فارغ=الكل)</label><input class="ainp" id="cp-wilayas" placeholder="الجزائر, وهران, ..."></div>
        <button class="btn-main" onclick="WOW._createCoupon()">انشاء كوبون</button>
      </div>
      <div id="cp-list"></div>
    </div>
    <!-- ARCHIVE -->
    <div class="adm-sec" id="sec-archive">
      <div class="adm-sec-title">الارشيف</div>
      <div style="display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap">
        <select class="ord-filter-inp" id="arch-cat-flt" onchange="WOW._loadArchive()">
          <option value="">كل الفئات</option>
          <option value="shirts">قمصان</option><option value="pants">بنطلونات</option>
          <option value="shorts">شورتات</option><option value="hats">قبعات</option>
          <option value="accessories">اكسسوار</option><option value="other">اخرى</option>
        </select>
        <button class="aibtn" onclick="WOW._archSelectAll()">تحديد الكل</button>
        <button class="aibtn" onclick="WOW._bulkRestore()">استعادة المحددة</button>
      </div>
      <div id="arch-list"></div>
    </div>
    <!-- ANALYTICS -->
    <div class="adm-sec" id="sec-analytics">
      <div class="adm-sec-title">الاحصائيات</div>
      <div class="kpi-grid" id="analytics-kpis"></div>
      <div class="chart-wrap"><div class="chart-title">الايراد — 14 يوم</div><svg id="revenue-chart" width="100%" height="110"></svg></div>
      <div class="chart-wrap" id="wilaya-heat-wrap"><div class="chart-title">التوزيع الجغرافي</div><div id="wilaya-heat-list"></div></div>
      <div class="kpi-grid" id="profit-kpis"></div>
      <div class="chart-wrap"><div class="chart-title">الاجهزة والانظمة (م2)</div><div id="device-report"></div></div>
    </div>
    <!-- VISITORS -->
    <div class="adm-sec" id="sec-visitors">
      <div class="adm-sec-title">الزوار</div>
      <div style="display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap">
        <button class="aibtn" onclick="if(confirm('مسح سجل الزوار؟'))WOW._clearVisitors()">مسح</button>
      </div>
      <div id="visitors-list"></div>
    </div>
    <!-- STOCK -->
    <div class="adm-sec" id="sec-stock">
      <div class="adm-sec-title">سجل المخزون</div>
      <div style="background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:14px;margin-bottom:14px">
        <div class="adm-row2">
          <div class="af"><label>المنتج</label><select class="ainp" id="stock-prod-sel"></select></div>
          <div class="af"><label>الكمية (+/-)</label><input class="ainp" id="stock-qty" type="number" placeholder="+10" inputmode="numeric"></div>
        </div>
        <div class="af"><label>السبب</label><input class="ainp" id="stock-reason" placeholder="استلام بضاعة / تعديل..."></div>
        <button class="btn-main" onclick="WOW._addStock()">تحديث المخزون</button>
      </div>
      <div id="stock-hist-list"></div>
    </div>
    <!-- REVIEWS -->
    <div class="adm-sec" id="sec-reviews">
      <div class="adm-sec-title">التقييمات والشهادات</div>
      <div style="display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap">
        <button class="aibtn on" id="rv-tab-reviews"       onclick="WOW._showRvTab('reviews',this)">التقييمات</button>
        <button class="aibtn"    id="rv-tab-testimonials"  onclick="WOW._showRvTab('testimonials',this)">الشهادات</button>
        <button class="aibtn"    id="rv-tab-add"           onclick="WOW._showRvTab('add',this)">اضافة شهادة</button>
      </div>
      <div id="sec-reviews-inner"></div>
    </div>
    <!-- LOYALTY -->
    <div class="adm-sec" id="sec-loyalty">
      <div class="adm-sec-title">نقاط الولاء</div>
      <div style="display:flex;gap:6px;margin-bottom:12px">
        <input class="ord-filter-inp" id="loy-search" placeholder="بحث برقم الهاتف..." style="flex:1" inputmode="tel">
        <button class="aibtn" onclick="WOW._loadLoyalty(document.getElementById('loy-search').value)">بحث</button>
      </div>
      <div id="loyalty-list"></div>
    </div>
    <!-- SETTINGS -->
    <div class="adm-sec" id="sec-settings">
      <div class="adm-sec-title">الاعدادات</div>
      <div class="af"><label>اسم المتجر</label><input class="ainp" id="s-name" value="${sn}"></div>
      <div class="af"><label>واتساب</label><input class="ainp" id="s-wa" type="tel" value="${wa}" inputmode="tel"></div>
      <div class="af"><label>البريد الالكتروني</label><input class="ainp" id="s-em" type="email" value="${em}" inputmode="email"></div>
      <div class="af"><label>انستغرام</label><input class="ainp" id="s-ig" value="${ig}"></div>
      <div class="af"><label>خصم عام %</label><input class="ainp" id="s-disc" type="number" min="0" max="90" value="${adminDisc}" inputmode="numeric"></div>
      <div class="af"><label>خلفية الصفحة (URL)</label><input class="ainp" id="s-bg" value="${s.hero_background||""}" placeholder="رابط صورة او فيديو"></div>
      <div class="af"><label>عن المتجر</label><textarea class="ainp" id="s-about" rows="3" style="resize:vertical">${s.about||""}</textarea></div>
      <div class="af"><label>الاسئلة الشائعة</label><textarea class="ainp" id="s-faq" rows="4" style="resize:vertical" placeholder="سؤال | جواب (سطر لكل زوج)">${s.faq||""}</textarea></div>
      <div class="af"><label>سياسة الارجاع</label><textarea class="ainp" id="s-refund" rows="3" style="resize:vertical">${s.refundPolicy||""}</textarea></div>
      <div class="af">
        <label>شريط الميزات (سطر لكل ميزة)</label>
        <textarea class="ainp" id="s-featbar" rows="4" style="resize:vertical">${(s.featuresBar||[]).join("\n")}</textarea>
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:8px">
          <label style="font-size:11px;color:var(--mu);display:flex;align-items:center;gap:5px;cursor:pointer"><input type="checkbox" id="s-show-featbar" ${s.showFeatureBar!==false?"checked":""} style="accent-color:#a855f7"> اظهار الشريط</label>
          <label style="font-size:11px;color:var(--mu);display:flex;align-items:center;gap:5px;cursor:pointer"><input type="checkbox" id="s-show-faq" ${s.showFaq!==false?"checked":""} style="accent-color:#a855f7"> اظهار FAQ</label>
          <label style="font-size:11px;color:var(--mu);display:flex;align-items:center;gap:5px;cursor:pointer"><input type="checkbox" id="s-show-refund" ${s.showRefundPolicy!==false?"checked":""} style="accent-color:#a855f7"> سياسة الارجاع</label>
          <label style="font-size:11px;color:var(--mu);display:flex;align-items:center;gap:5px;cursor:pointer"><input type="checkbox" id="s-show-badges" ${s.showTrustBadges!==false?"checked":""} style="accent-color:#a855f7"> شارات الثقة</label>
        </div>
      </div>
      <div class="af"><label>لغة الموقع</label>
        <select class="ainp" id="s-lang">
          <option value="ar" ${lang==="ar"?"selected":""}>عربي (RTL)</option>
          <option value="fr" ${lang==="fr"?"selected":""}>Francais (LTR)</option>
          <option value="en" ${lang==="en"?"selected":""}>English (LTR)</option>
        </select>
      </div>
      <button class="btn-main" id="save-settings-btn">حفظ الاعدادات</button>
      <div style="margin-top:16px;padding-top:14px;border-top:1px solid rgba(255,255,255,.06)">
        <button class="adm-close" onclick="WOW.closeAdm()">تسجيل الخروج</button>
      </div>
    </div>
    <!-- ACTIVITY LOG -->
    <div class="adm-sec" id="sec-activity">
      <div class="adm-sec-title">سجل العمليات</div>
      <div style="display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap">
        <select class="ord-filter-inp" id="act-type-flt" onchange="WOW._loadActivity()">
          <option value="">كل الانواع</option>
          <option value="admin_login">دخول</option>
          <option value="product_create">اضافة منتج</option>
          <option value="product_update">تعديل منتج</option>
          <option value="product_delete">حذف منتج</option>
          <option value="product_archive">ارشفة</option>
          <option value="order_status">تغيير حالة</option>
          <option value="duplicate_order">طلب مكرر</option>
          <option value="stock_alert">تنبيه مخزون</option>
          <option value="settings_update">الاعدادات</option>
          <option value="coupon_create">كوبون جديد</option>
        </select>
        <input class="ord-filter-inp" id="act-actor-flt" placeholder="system, admin..." oninput="WOW._loadActivity()" style="max-width:130px">
      </div>
      <div id="activity-list"></div>
    </div>
  </div>
</div>
<!-- TOAST -->
<div class="toast" id="toast" role="status" aria-live="polite"></div>
<script>
var WOW=(function(){
"use strict";
// ── State ──
var _prods=[],_cart=[],_adminToken=null,_currentProd=null;
var _couponApplied=null,_selectedSize=null,_selectedColor=null;
var _prodImgs=[],_editingId=null,_ordersCache=[],_bulkSelected=new Set();
var _archSelected=new Set();
var _noteDebounce={};
var _cdCallback=null,_cdHoldTimer=null,_cdHoldInterval=null;
var _langActive="ar";
var _dragSrc=null;
var _filterState={search:"",status:"",wilaya:"",confirmed:""};
var _ratingVal=5;

// ── Session Storage ──
function _saveSession(tok){try{sessionStorage.setItem("wow_tok",tok);}catch(e){}}
function _restoreSession(){try{var t=sessionStorage.getItem("wow_tok");if(t){_adminToken=t;return true;}}catch(e){}return false;}
function _clearSession(){try{sessionStorage.removeItem("wow_tok");}catch(e){}_adminToken=null;}

// ── Visitor Tracking ──
var _visitorId=(function(){
  try{var v=localStorage.getItem("wow_vid");if(!v){v=Math.random().toString(36).slice(2)+Date.now().toString(36);localStorage.setItem("wow_vid",v);}return v;}
  catch(e){return "v"+Math.random().toString(36).slice(2);}
})();
var _pageStart=Date.now();
function _trackVisit(){
  var src="Direct";
  try{var r=document.referrer;if(r){if(r.includes("google")||r.includes("bing"))src="Search";else if(r.includes("facebook")||r.includes("instagram"))src="Social";else src="Referral";}}catch(e){}
  fetch("/api/analytics",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({vid:_visitorId,source:src,bounced:true})}).catch(function(){});
  window.addEventListener("beforeunload",function(){
    var dur=Math.round((Date.now()-_pageStart)/1000);
    navigator.sendBeacon("/api/analytics",new Blob([JSON.stringify({vid:_visitorId,source:src,duration:dur,bounced:dur<10})],{type:"application/json"}));
  });
}

// ── API Helper ──
function _api(url,opts){
  var o=opts||{};
  var headers={"Content-Type":"application/json"};
  if(_adminToken)headers["X-Admin-Key"]=_adminToken;
  Object.assign(headers,o.headers||{});
  return fetch(url,Object.assign({},o,{headers:headers})).then(function(r){
    if(r.status===204)return {};
    return r.json().then(function(d){
      if(!r.ok)throw d;
      return d;
    });
  });
}

// ── Toast ──
function _toast(msg,dur){
  var t=document.getElementById("toast");if(!t)return;
  t.textContent=msg;t.classList.add("on");
  clearTimeout(_toast._t);
  _toast._t=setTimeout(function(){t.classList.remove("on");},dur||2600);
}

// ── Escape ──
function _esc(s){
  return String(s||"")
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;")
    .replace(/'/g,"&#39;");
}
function _fmtP(n){return Number(n||0).toLocaleString("ar-DZ")+" دج";}

// ── Scroll Progress ──
function _initScrollProg(){
  var prog=document.getElementById("scroll-prog");
  var hdr=document.getElementById("main-hdr");
  if(!prog)return;
  window.addEventListener("scroll",function(){
    var s=document.documentElement;
    var pct=(s.scrollTop||document.body.scrollTop)/(s.scrollHeight-s.clientHeight||1);
    prog.style.transform="scaleX("+Math.min(1,pct)+")";
    if(hdr)hdr.classList.toggle("scrolled",(s.scrollTop||document.body.scrollTop)>40);
  },{passive:true});
}

// ── Hero Background ──
function _initHero(bg){
  if(!bg)return;
  var hero=document.getElementById("hero-bg");if(!hero)return;
  var isVid=/\.(mp4|webm|ogg)(\?.*)?$/i.test(bg);
  if(isVid){
    var v=document.createElement("video");
    v.src=bg;v.autoplay=true;v.muted=true;v.loop=true;v.playsInline=true;
    v.className="hero-bg-media";v.setAttribute("aria-hidden","true");
    hero.insertBefore(v,hero.querySelector(".hero-bg-overlay"));
  } else {
    var img=document.createElement("img");
    img.src=bg;img.className="hero-bg-media is-img";img.alt="";img.setAttribute("aria-hidden","true");
    hero.insertBefore(img,hero.querySelector(".hero-bg-overlay"));
  }
}

// ── م46: Keyboard Shortcuts ──
function _initKeyboard(){
  document.addEventListener("keydown",function(e){
    if(e.target.tagName==="INPUT"||e.target.tagName==="TEXTAREA"||e.target.tagName==="SELECT")return;
    switch(e.key){
      case"Escape":
        document.querySelectorAll(".mod-ov.on,.cart-sb.on,.adm-ov.on,.confirm-del-ov.on").forEach(function(el){el.classList.remove("on");});
        document.getElementById("cart-ov")&&document.getElementById("cart-ov").classList.remove("on");
        break;
      case"f":case"F":_toggleFullscreen();break;
      case"c":case"C":
        if(_adminToken){_api("/api/orders").then(function(o){_ordersCache=o||[];_filterOrders();}).catch(function(){});}
        break;
    }
  });
}

// ── م46: Fullscreen ──
function _toggleFullscreen(){
  try{
    if(!document.fullscreenElement&&!document.webkitFullscreenElement){
      (document.documentElement.requestFullscreen||document.documentElement.webkitRequestFullscreen||function(){}).call(document.documentElement);
    } else {
      (document.exitFullscreen||document.webkitExitFullscreen||function(){}).call(document);
    }
  }catch(e){}
}

// ── Admin Auth ──
function _openAdm(){
  if(_restoreSession()){_verifyToken();}
  else{var ov=document.getElementById("adm-login-ov");if(ov)ov.classList.add("on");setTimeout(function(){var p=document.getElementById("adm-pass");if(p)p.focus();},150);}
}
function _verifyToken(){
  _api("/api/auth-verify",{method:"POST"}).then(function(d){
    if(d.ok)_showAdm();
    else{_clearSession();var ov=document.getElementById("adm-login-ov");if(ov)ov.classList.add("on");}
  }).catch(function(){_clearSession();var ov=document.getElementById("adm-login-ov");if(ov)ov.classList.add("on");});
}
function _doLogin(){
  var p=document.getElementById("adm-pass"),msg=document.getElementById("adm-login-msg"),btn=document.getElementById("adm-login-btn");
  if(!p)return;
  var pass=p.value;if(!pass)return;
  if(btn){btn.disabled=true;btn.textContent="...";}
  if(msg)msg.textContent="";
  _api("/api/auth",{method:"POST",body:JSON.stringify({password:pass})}).then(function(d){
    if(btn){btn.disabled=false;btn.textContent="دخول";}
    if(d.ok){
      _adminToken=d.token;_saveSession(d.token);
      var ov=document.getElementById("adm-login-ov");if(ov)ov.classList.remove("on");
      p.value="";_showAdm();
    } else {
      if(msg)msg.textContent=d.stall?"حساب مقفل مؤقتاً":"كلمة مرور خاطئة"+(d.remaining?" ("+d.remaining+" محاولة)":"");
    }
  }).catch(function(){if(btn){btn.disabled=false;btn.textContent="دخول";}if(msg)msg.textContent="خطأ في الاتصال";});
}
function _showAdm(){
  var el=document.getElementById("adm-ov");if(el)el.classList.add("on");
  _aTab("dash",null);_loadProds();_loadKvStats();
}
function closeAdm(){
  _api("/api/logout",{method:"POST"}).catch(function(){});
  _clearSession();
  var el=document.getElementById("adm-ov");if(el)el.classList.remove("on");
}

// ── Tabs ──
function _aTab(name,el){
  document.querySelectorAll(".adm-sec").forEach(function(s){s.classList.remove("on");});
  document.querySelectorAll(".adm-tab").forEach(function(t){t.classList.remove("on");});
  var sec=document.getElementById("sec-"+name);if(sec)sec.classList.add("on");
  var tab=document.getElementById("tab-"+name);if(tab)tab.classList.add("on");
  if(el)el.classList.add("on");
  var loaders={orders:_loadOrders,products:_loadProds,analytics:_loadAnalytics,visitors:_loadVisitors,coupons:_loadCoupons,archive:_loadArchive,stock:_loadStockHistory,reviews:_loadReviews,loyalty:function(){_loadLoyalty("");},activity:_loadActivity,dash:function(){_loadDash();_loadOrders();},addprod:function(){}};
  if(loaders[name])loaders[name]();
}

// ── Dashboard ──
function _loadDash(){
  _api("/api/analytics").then(function(d){
    var g=document.getElementById("dash-kpis");if(!g)return;
    var wkD=d.revLastWeek>0?Math.round((d.revThisWeek-d.revLastWeek)/d.revLastWeek*100):0;
    g.innerHTML=[
      {l:"مبيعات الاسبوع",v:_fmtP(d.revThisWeek),s:(wkD>=0?"+":"")+wkD+"%",c:wkD>=0?"kpi-good":"kpi-bad"},
      {l:"الطلبيات الكلية",v:d.totalOrders||0,s:""},
      {l:"نسبة التاكيد",v:(d.confirmRate||0)+"%",s:d.confirmedOrders+" مؤكدة"},
      {l:"متوسط الطلب",v:_fmtP(d.avgOrderVal),s:""},
      {l:"زوار فريدون",v:d.uniqueVisitors||0,s:d.totalVisits+" زيارة"},
      {l:"المنتجات",v:d.productCount||0,s:""},
    ].map(function(k){return'<div class="kpi-card"><div class="kpi-label">'+_esc(k.l)+'</div><div class="kpi-val">'+k.v+'</div><div class="kpi-sub '+( k.c||"")+'">'+_esc(k.s)+'</div></div>';}).join("");
    _drawChart(d.dailySales,"sales-chart");
    _checkLowStock();
  }).catch(function(){});
}

// ── KV Stats ──
function _loadKvStats(){
  _api("/api/kv-stats").then(function(d){
    var el=document.getElementById("kv-stats-bar");if(!el)return;
    var pct=Math.min(100,d.pctUsed||0);
    el.innerHTML='<div style="display:flex;justify-content:space-between;font-size:10px;color:var(--mu);margin-bottom:5px"><span>'+d.usedMB+' MB</span><span>'+pct+'% مستخدم</span></div>'
      +'<div style="height:5px;background:rgba(255,255,255,.06);border-radius:3px;overflow:hidden"><div style="height:100%;width:'+pct+'%;background:linear-gradient(90deg,#6d28d9,#a855f7);border-radius:3px"></div></div>'
      +'<div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:7px">'
      +(d.keyDetails||[]).map(function(k){return'<span style="font-size:9px;color:var(--mu);background:rgba(255,255,255,.03);padding:2px 6px;border-radius:4px">'+_esc(k.key)+': '+(k.bytes/1024).toFixed(1)+'KB</span>';}).join("")
      +'</div>';
  }).catch(function(){});
}

// ── م15: SVG Chart ──
function _drawChart(dailySales,svgId){
  var svg=document.getElementById(svgId);if(!svg)return;
  var keys=Object.keys(dailySales||{}).sort().slice(-14);
  if(!keys.length){svg.innerHTML="";return;}
  var vals=keys.map(function(k){return(dailySales[k].orders||0);});
  var maxV=Math.max.apply(null,vals)||1;
  var W=svg.parentElement?svg.parentElement.clientWidth||320:320;
  var H=90,pad=12;
  var step=keys.length>1?(W-pad*2)/(keys.length-1):W-pad*2;
  var pts=vals.map(function(v,i){return[(pad+i*step).toFixed(1),(H-pad-(v/maxV)*(H-pad*2)).toFixed(1)].join(",");}).join(" ");
  svg.setAttribute("viewBox","0 0 "+W+" "+H);
  svg.innerHTML=
    '<polyline fill="none" stroke="rgba(168,85,247,.65)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" points="'+pts+'"/>'
    +vals.map(function(v,i){
      var cx=(pad+i*step).toFixed(1),cy=(H-pad-(v/maxV)*(H-pad*2)).toFixed(1);
      return'<circle cx="'+cx+'" cy="'+cy+'" r="3" fill="#a855f7" title="'+v+'"/>'
        +'<text x="'+cx+'" y="'+(+cy-6)+'" text-anchor="middle" font-size="8" fill="rgba(255,255,255,.3)">'+v+'</text>';
    }).join("")
    +'<text x="'+pad+'" y="'+H+'" font-size="8" fill="rgba(255,255,255,.2)" font-family="monospace">'+keys[0]+'</text>'
    +'<text x="'+(W-pad)+'" y="'+H+'" font-size="8" fill="rgba(255,255,255,.2)" font-family="monospace" text-anchor="end">'+keys[keys.length-1]+'</text>';
}

// ── م27: Low Stock Alert ──
function _checkLowStock(){
  _api("/api/products").then(function(prods){
    var low=prods.filter(function(p){return p.quantity!==null&&p.quantity!==undefined&&p.quantity<=(p.alertQty||5)&&!p.archived;});
    var wrap=document.getElementById("alert-low-stock"),list=document.getElementById("alert-low-stock-list");
    if(!wrap||!list)return;
    if(low.length){
      wrap.style.display="block";
      list.innerHTML=low.map(function(p){return'<div style="margin-bottom:3px">'+_esc(p.name)+'<strong style="margin-right:4px"> '+p.quantity+'</strong> متبقية</div>';}).join("");
    }else wrap.style.display="none";
  }).catch(function(){});
}

// ── Products ──
function _loadProds(){
  _api("/api/products").then(function(prods){
    _prods=prods||[];
    _renderGrid(_prods);
    _renderAdminProds(_prods);
    Promise.all([_api("/api/bundles"),_api("/api/testimonials")]).then(function(res){
      _renderBundles(res[0]||[]);_renderTestimonials(res[1]||[]);
    }).catch(function(){});
  }).catch(function(){_renderGrid([]);});
}

// ── Grid Render ──
function _renderGrid(prods){
  var g=document.getElementById("prod-grid");if(!g)return;
  var vis=prods.filter(function(p){return!p.archived;});
  if(!vis.length){g.innerHTML='<div class="empty">لا توجد منتجات</div>';return;}
  g.innerHTML=vis.map(function(p){
    var imgs=p.images&&p.images.length?p.images:[""];
    var effDisc=p.flashDisc||p.discount||0;
    var effPrice=effDisc>0?Math.round(p.price*(1-effDisc/100)):p.price;
    var isFlash=!!p.flashDisc;
    var scarceLow=p.quantity!==null&&p.quantity!==undefined&&p.quantity>0&&p.quantity<=10;
    var imgHTML=imgs.map(function(src,i){
      return'<img src="'+_esc(src)+'" alt="'+_esc(p.name)+'" loading="'+(i===0?"eager":"lazy")+'" class="'+(i===0?"active ":"")+'lazy-blur" onload="this.classList.add(\'lazy-loaded\')" onerror="this.style.display=\'none\'">';
    }).join("");
    var dots=imgs.length>1?'<div class="slide-dots">'+imgs.map(function(_,i){return'<div class="slide-dot'+(i===0?" on":"")+'" onclick="WOW.sTo('+p.id+','+i+',event)"></div>';}).join("")+'</div>':"";
    var arrs=imgs.length>1?'<button class="slide-arr prev" onclick="WOW.sPrev('+p.id+',event)" aria-label="السابق">&#8249;</button><button class="slide-arr next" onclick="WOW.sNext('+p.id+',event)" aria-label="التالي">&#8250;</button>':"";
    return'<div class="card" onclick="WOW.openProd('+p.id+')" id="card-'+p.id+'" role="article">'
      +(isFlash?'<div class="card-flash-strip"><span>FLASH -'+effDisc+'%</span><span class="flash-timer" id="ft-'+p.id+'"></span></div>':"")
      +'<div class="img-slider" id="sl-'+p.id+'">'+arrs+imgHTML+dots+'</div>'
      +'<div class="card-body">'
      +'<div class="card-cat">'+_esc(p.cat||"")+'</div>'
      +'<div class="card-name">'+_esc(p.name)+'</div>'
      +'<div class="price-wrap"><span class="card-price">'+_fmtP(effPrice)+'</span>'
      +(effDisc>0?'<span class="card-price-old">'+_fmtP(p.price)+'</span><span class="disc-badge">-'+effDisc+'%</span>':"")
      +'</div>'
      +(p.salesCount>0?'<div class="sales-counter">'+p.salesCount+' مبيعة</div>':"")
      +(scarceLow?'<div class="scarcity-bar"><div class="scarcity-fill scarcity-low" style="width:'+Math.round(p.quantity/10*100)+'%"></div></div><div class="scarcity-txt">متبقي '+p.quantity+' فقط</div>':"")
      +'<button class="addbtn" onclick="event.stopPropagation();WOW.openProd('+p.id+')" aria-label="اضافة للسلة">اضافة للسلة</button>'
      +'</div></div>';
  }).join("");
  vis.filter(function(p){return p.flashEndAt;}).forEach(function(p){_startFlashTimer(p.id,p.flashEndAt);});
  _initLazy();
}

// ── Flash Timer ──
function _startFlashTimer(id,endAt){
  var el=document.getElementById("ft-"+id);if(!el)return;
  (function tick(){
    var diff=new Date(endAt).getTime()-Date.now();
    if(diff<=0){el.textContent="انتهى";return;}
    var h=Math.floor(diff/3600000),m=Math.floor(diff%3600000/60000),s=Math.floor(diff%60000/1000);
    el.textContent=(h?h+"h ":"")+m+"m "+s+"s";
    setTimeout(tick,1000);
  })();
}

// ── Lazy Load ──
function _initLazy(){
  if(!("IntersectionObserver"in window))return;
  var obs=new IntersectionObserver(function(entries){
    entries.forEach(function(e){
      if(!e.isIntersecting)return;
      var img=e.target;var src=img.getAttribute("data-src");
      if(src){img.src=src;img.removeAttribute("data-src");}
      obs.unobserve(img);
    });
  },{rootMargin:"200px"});
  document.querySelectorAll("img[data-src]").forEach(function(img){obs.observe(img);});
}

// ── Image Slider Controls ──
function _sTo(id,idx,e){if(e)e.stopPropagation();_goSlide(id,idx);}
function _sPrev(id,e){if(e)e.stopPropagation();var sl=document.getElementById("sl-"+id);if(!sl)return;var imgs=sl.querySelectorAll("img"),cur=_curSlide(imgs);_goSlide(id,(cur-1+imgs.length)%imgs.length);}
function _sNext(id,e){if(e)e.stopPropagation();var sl=document.getElementById("sl-"+id);if(!sl)return;var imgs=sl.querySelectorAll("img"),cur=_curSlide(imgs);_goSlide(id,(cur+1)%imgs.length);}
function _curSlide(imgs){for(var i=0;i<imgs.length;i++)if(imgs[i].classList.contains("active"))return i;return 0;}
function _goSlide(id,idx){
  var sl=document.getElementById("sl-"+id);if(!sl)return;
  var imgs=sl.querySelectorAll("img"),dots=sl.querySelectorAll(".slide-dot");
  imgs.forEach(function(im,i){im.classList.toggle("active",i===idx);});
  dots.forEach(function(d,i){d.classList.toggle("on",i===idx);});
}

// ── م8: Filters ──
function _flt(cat,el){
  document.querySelectorAll(".flt-btn").forEach(function(b){b.classList.remove("on");});
  if(el)el.classList.add("on");
  var res;
  if(cat==="all")res=_prods;
  else if(cat==="new")res=_prods.filter(function(p){return Date.now()-p.createdAt<7*86400000;});
  else if(cat==="top")res=[..._prods].sort(function(a,b){return(b.salesCount||0)-(a.salesCount||0);});
  else res=_prods.filter(function(p){return p.cat===cat;});
  _renderGrid(res);
}

// ── Live Search ──
function _liveSearch(q){
  var s=(q||"").toLowerCase().trim();
  if(!s){_renderGrid(_prods);return;}
  _renderGrid(_prods.filter(function(p){return(p.name||"").toLowerCase().includes(s)||(p.desc||"").toLowerCase().includes(s);}));
}

// ── Product Modal ──
function _openProd(id){
  var p=_prods.find(function(x){return String(x.id)===String(id);});if(!p){return;}
  _currentProd=p;_selectedSize=null;_selectedColor=null;
  fetch("/api/products/track",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:p.id,event:"view"})}).catch(function(){});
  document.getElementById("mod-ov").classList.add("on");
  var D=function(i,v){var el=document.getElementById(i);if(el)el.textContent=v||"";};
  D("mod-cat",p.cat||"");D("mod-name",p.name||"");D("mod-desc",p.desc||"");
  var effDisc=p.flashDisc||p.discount||0,effPrice=effDisc>0?Math.round(p.price*(1-effDisc/100)):p.price;
  var pr=document.getElementById("mod-price"),op=document.getElementById("mod-old-price"),db=document.getElementById("mod-disc-badge");
  if(pr)pr.textContent=_fmtP(effPrice);
  if(effDisc>0){if(op)op.textContent=_fmtP(p.price);if(db){db.textContent="-"+effDisc+"%";db.style.display="inline-block";}}
  else{if(op)op.textContent="";if(db)db.style.display="none";}
  // Gallery
  var imgs=p.images&&p.images.length?p.images:[];
  var mi=document.getElementById("pm-main-img");
  if(mi&&imgs[0]){mi.src=imgs[0];mi.classList.remove("lazy-loaded");}
  var th=document.getElementById("pm-thumbs");
  if(th)th.innerHTML=imgs.map(function(src,i){return'<img src="'+_esc(src)+'" class="gal-thumb'+(i===0?" on":"")+'" loading="lazy" onclick="WOW.pmImg(\''+_esc(src)+'\',this)" alt="">';}).join("");
  // Sizes
  var szEl=document.getElementById("mod-sizes");
  if(szEl)szEl.innerHTML=p.sizes&&p.sizes.length
    ?'<div style="font-size:10px;color:var(--mu);margin-bottom:6px;letter-spacing:1px">المقاس</div>'
     +'<div class="sz-row">'+p.sizes.map(function(sz){return'<button class="sz-btn" onclick="WOW.pickSz(this,\''+_esc(sz)+'\')" aria-label="'+_esc(sz)+'">'+_esc(sz)+'</button>';}).join("")+'</div>'
     +'<button style="background:none;border:none;color:rgba(168,85,247,.5);font-size:10px;cursor:pointer;padding:4px 0;font-family:inherit;-webkit-tap-highlight-color:transparent" onclick="WOW.openSizeMod(true)">دليل المقاسات</button>'
    :"";
  // Colors
  var clEl=document.getElementById("mod-colors");
  if(clEl)clEl.innerHTML=p.colors&&p.colors.length
    ?'<div style="font-size:10px;color:var(--mu);margin-bottom:6px;letter-spacing:1px">اللون</div>'
     +'<div class="sz-row">'+p.colors.map(function(c){return'<button class="sz-btn" onclick="WOW.pickClr(this,\''+_esc(c)+'\')" aria-label="'+_esc(c)+'">'+_esc(c)+'</button>';}).join("")+'</div>'
    :"";
  // م26: Variants
  var vrEl=document.getElementById("mod-variants");
  if(vrEl)vrEl.innerHTML=p.variants&&p.variants.length
    ?'<div style="font-size:10px;color:var(--mu);margin-bottom:6px;letter-spacing:1px">المتغيرات</div>'
     +'<div style="display:flex;flex-wrap:wrap;gap:6px">'+p.variants.filter(function(v){return v.qty>0;}).map(function(v){return'<button class="var-chip" onclick="WOW.pickVariant(this,\''+_esc(v.size||"")+'\',\''+_esc(v.color||"")+'\')">'+(v.size?_esc(v.size)+" ":"")+(v.color?_esc(v.color):"")+" ("+v.qty+")</button>";}).join("")+'</div>'
    :"";
  // Scarcity
  var sc=document.getElementById("mod-scarcity");
  if(sc)sc.innerHTML=p.quantity!==null&&p.quantity!==undefined&&p.quantity>0&&p.quantity<=10
    ?'<div class="scarcity-bar"><div class="scarcity-fill scarcity-low" style="width:'+Math.round(p.quantity/10*100)+'%"></div></div><div class="scarcity-txt">متبقي '+p.quantity+' فقط</div>':"";
  // Waitlist
  var wl=document.getElementById("mod-waitlist");
  if(wl)wl.innerHTML=p.quantity===0||p.stock===false?'<button class="waitlist-btn" onclick="WOW._joinWaitlist('+p.id+')">تنبيهني عند التوفر</button>':"";
  // Rating
  var rt=document.getElementById("mod-rating");
  if(rt)rt.innerHTML=p.reviewCount
    ?'<div style="font-size:11px;color:#f59e0b">'+"&#9733;".repeat(Math.round(p.avgRating||5))+'<span style="color:var(--mu);margin-right:5px">('+p.reviewCount+')</span></div>':"";
  // Qty
  var qi=document.getElementById("mod-qty");if(qi)qi.value=1;
  _loadProdReviews(p.id);
  // م29: QR
  _genQR(location.origin+"/p/"+p.id);
}
function _closeMod(){
  var el=document.getElementById("mod-ov");if(el)el.classList.remove("on");
  _currentProd=null;_selectedSize=null;_selectedColor=null;
}
function pmImg(src,el){
  var mi=document.getElementById("pm-main-img");if(!mi)return;
  mi.src=src;
  document.querySelectorAll(".gal-thumb").forEach(function(x){x.classList.remove("on");});
  if(el)el.classList.add("on");
}
function pickSz(el,sz){
  _selectedSize=sz;
  document.querySelectorAll(".sz-btn").forEach(function(b){b.classList.remove("on");});
  if(el)el.classList.add("on");
}
function pickClr(el,c){
  _selectedColor=c;
  document.querySelectorAll(".sz-btn").forEach(function(b){b.classList.remove("on");});
  if(el)el.classList.add("on");
}
function pickVariant(el,sz,cl){
  _selectedSize=sz||null;_selectedColor=cl||null;
  document.querySelectorAll(".var-chip").forEach(function(b){b.classList.remove("on");});
  if(el)el.classList.add("on");
}
function openSizeMod(open){
  var el=document.getElementById("size-mod-ov");if(!el)return;
  if(open){
    el.classList.add("on");
    var g=document.getElementById("size-guide-grid");if(!g)return;
    var rows=[["S","34-36","58-60","70-72"],["M","38-40","62-64","74-76"],["L","42-44","66-68","78-80"],["XL","46-48","70-72","82-84"],["XXL","50-52","74-76","86-88"]];
    var hdrs=["المقاس","الصدر","الخصر","الورك"];
    g.innerHTML='<div style="display:contents">'+hdrs.map(function(h){return'<div style="font-size:9px;color:var(--mu);padding:5px;letter-spacing:1px">'+h+'</div>';}).join("")+'</div>'
      +rows.map(function(r){return'<div style="display:contents">'+r.map(function(c,i){return'<div style="background:rgba(255,255,255,.03);padding:7px;border-radius:6px;font-size:'+(i===0?"11":"10")+'px;color:'+(i===0?"rgba(192,132,252,.8)":"var(--dim)")+'">'+c+'</div>';}).join("")+'</div>';}).join("");
  }else el.classList.remove("on");
}

// ── م29: QR Generator (SVG محلي) ──
function _genQR(url){
  var el=document.getElementById("qr-content");if(!el)return;
  // Simple visual QR placeholder — URL encoded in barcode style
  var size=140,mod=Math.ceil(size/21);
  var hash=0;for(var i=0;i<url.length;i++)hash=(hash*31+url.charCodeAt(i))&0x7fffffff;
  var cells=[];
  for(var r=0;r<21;r++){cells[r]=[];for(var c2=0;c2<21;c2++){
    // Finder patterns corners
    var inFP=(r<7&&c2<7)||(r<7&&c2>13)||(r>13&&c2<7);
    var bitPos=r*21+c2;var bitVal=((hash>>>(bitPos%31))&1)===1;
    cells[r][c2]=inFP||(r===6||c2===6)?(r+c2)%2===0:bitVal;
  }}
  var svg='<svg xmlns="http://www.w3.org/2000/svg" width="'+size+'" height="'+size+'">';
  for(var rr=0;rr<21;rr++)for(var cc=0;cc<21;cc++)if(cells[rr][cc])svg+='<rect x="'+(cc*mod)+'" y="'+(rr*mod)+'" width="'+mod+'" height="'+mod+'" fill="#111"/>';
  svg+='</svg>';
  el.innerHTML=svg;
}
function _showQR(){document.getElementById("qr-ov").classList.add("on");}
function _copyProdLink(){
  if(!_currentProd)return;
  var link=location.origin+"/p/"+_currentProd.id;
  navigator.clipboard&&navigator.clipboard.writeText(link).then(function(){_toast("تم نسخ الرابط");}).catch(function(){});
}

// ── Waitlist ──
function _joinWaitlist(id){
  var p=_prods.find(function(x){return x.id===id;});
  var phone=prompt("ادخل رقم هاتفك للتنبيه:");
  if(!phone||!/^0[567]\d{8}$/.test(phone.replace(/\s/g,""))){_toast("رقم غير صالح");return;}
  _api("/api/waitlist",{method:"POST",body:JSON.stringify({phone:phone.replace(/\s/g,""),productId:id,productName:p?p.name:""})})
  .then(function(d){_toast(d.msg||"تم التسجيل");}).catch(function(){_toast("خطأ");});
}

// ── Reviews ──
function _loadProdReviews(pid){
  var sec=document.getElementById("mod-review-section");if(!sec)return;
  _api("/api/reviews?productId="+pid).then(function(revs){
    if(!revs.length){sec.innerHTML='<button class="waitlist-btn" onclick="WOW._openReviewMod('+pid+')">اكتب تقييماً</button>';return;}
    sec.innerHTML='<div style="margin-bottom:8px;display:flex;justify-content:space-between;align-items:center"><span style="font-size:10px;color:var(--mu)">التقييمات ('+revs.length+')</span><button class="aibtn" style="font-size:10px" onclick="WOW._openReviewMod('+pid+')">اضافة</button></div>'
      +revs.slice(0,3).map(function(r){return'<div class="rv-card"><div class="rv-card-stars">'+"&#9733;".repeat(r.rating||5)+'</div><div class="rv-card-body">'+_esc(r.body||"")+'</div><div class="rv-card-name">'+_esc(r.name||"")+'</div></div>';}).join("");
  }).catch(function(){sec.innerHTML="";});
}
function _openReviewMod(pid){
  document.getElementById("rv-prod-id").value=pid;
  _ratingVal=5;
  var stars=document.getElementById("rv-stars");
  if(stars){stars.innerHTML=[1,2,3,4,5].map(function(n){return'<button onclick="WOW._setRating('+n+')" data-r="'+n+'" style="background:none;border:none;cursor:pointer;font-size:22px;color:'+(n<=_ratingVal?"#f59e0b":"rgba(255,255,255,.2)")+';-webkit-tap-highlight-color:transparent;min-width:36px;min-height:36px">&#9733;</button>';}).join("");}
  document.getElementById("review-mod-ov").classList.add("on");
}
function _setRating(n){
  _ratingVal=n;
  document.querySelectorAll("#rv-stars button").forEach(function(b){b.style.color=Number(b.dataset.r)<=n?"#f59e0b":"rgba(255,255,255,.2)";});
}
function _submitReview(){
  var pid=document.getElementById("rv-prod-id").value;
  var name=document.getElementById("rv-name")?.value.trim();
  var phone=document.getElementById("rv-phone")?.value.replace(/\s/g,"");
  var body2=document.getElementById("rv-body")?.value.trim();
  if(!name){_toast("ادخل اسمك");return;}
  _api("/api/reviews",{method:"POST",body:JSON.stringify({productId:+pid,name:name,phone:phone,body:body2,rating:_ratingVal})})
  .then(function(d){_toast(d.msg||"تم ارسال التقييم");document.getElementById("review-mod-ov").classList.remove("on");})
  .catch(function(e){_toast((e&&e.error)||"خطأ");});
}

// ── Bundles ──
function _renderBundles(bundles){
  var el=document.getElementById("bundles-section");if(!el)return;
  var act=bundles.filter(function(b){return b.active;});
  if(!act.length){el.style.display="none";return;}
  el.style.display="block";
  el.innerHTML='<div style="font-size:10px;color:var(--mu);letter-spacing:2px;text-transform:uppercase;margin-bottom:12px">الحزم</div>'
    +'<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px">'
    +act.map(function(b){
      var pImgs=(b.productIds||[]).map(function(pid){var p=_prods.find(function(x){return String(x.id)===String(pid);});return p&&p.images&&p.images[0]?'<img src="'+_esc(p.images[0])+'" class="bundle-img" alt="" loading="lazy">':'';}).join("");
      return'<div class="bundle-card" onclick="WOW._addBundle('+JSON.stringify(b.productIds)+')">'
        +'<div class="bundle-imgs">'+pImgs+'</div>'
        +'<div style="font-size:13px;font-weight:600;color:rgba(192,132,252,.9);margin-bottom:4px">'+_esc(b.name||"")+'</div>'
        +'<span class="bundle-disc-badge">وفر '+b.discVal+'%</span>'
        +'</div>';
    }).join("")+'</div>';
}
function _addBundle(ids){
  if(!Array.isArray(ids))return;
  ids.forEach(function(pid){
    var p=_prods.find(function(x){return String(x.id)===String(pid);});if(!p)return;
    var effDisc=p.discount||0,effPrice=effDisc>0?Math.round(p.price*(1-effDisc/100)):p.price;
    var ex=_cart.findIndex(function(c){return c.id===p.id;});
    if(ex>=0)_cart[ex].qty=Math.min(99,_cart[ex].qty+1);
    else _cart.push({id:p.id,name:p.name,price:effPrice,qty:1,size:"",color:"",img:(p.images&&p.images[0])||""});
  });
  _renderCart();_toast("تمت اضافة الحزمة للسلة");
}

// ── Testimonials ──
function _renderTestimonials(tl){
  var el=document.getElementById("testimonials-section");if(!el)return;
  if(!tl.length){el.style.display="none";return;}
  el.style.display="block";
  el.innerHTML='<div style="font-size:10px;color:var(--mu);letter-spacing:2px;text-transform:uppercase;margin-bottom:12px">شهادات العملاء</div>'
    +'<div style="display:flex;gap:12px;overflow-x:auto;scrollbar-width:none;-webkit-overflow-scrolling:touch;padding-bottom:6px">'
    +tl.map(function(t){return'<div class="tcard">'
      +'<div class="tcard-stars">'+"&#9733;".repeat(t.rating||5)+'</div>'
      +'<div class="tcard-body">'+_esc(t.body||"")+'</div>'
      +'<div class="tcard-name">'+_esc(t.name||"")+'</div>'
      +'</div>';}).join("")+'</div>';
}

// ── Trust Badges & FAQ ──
function _renderTrustBadges(){
  var el=document.getElementById("trust-badges-footer");if(!el)return;
  var badges=[["ضمان الجودة","QA"],["شحن آمن","SC"],["دفع آمن","PY"],["75% استرجاع","RF"]];
  el.innerHTML='<div class="trust-badges">'+badges.map(function(b){return'<div class="trust-badge"><span style="font-size:11px;color:rgba(168,85,247,.4)">'+b[1]+'</span><span>'+b[0]+'</span></div>';}).join("")+'</div>';
}
function _openFaq(){
  var el=document.getElementById("faq-ov"),cnt=document.getElementById("faq-content");
  if(!el||!cnt)return;
  var raw="${_esc(s.faq||"")}";
  if(!raw.trim()){cnt.innerHTML='<div style="color:var(--mu);font-size:12px;text-align:center;padding:20px">لا توجد اسئلة</div>';el.classList.add("on");return;}
  cnt.innerHTML=raw.split("\n").filter(Boolean).map(function(line){
    var parts=line.split("|");var q=parts[0]||"",a=parts[1]||"";
    return'<div class="faq-item"><div class="faq-q" onclick="var ans=this.nextElementSibling;ans.style.display=ans.style.display===\'block\'?\'none\':\'block\'">'
      +_esc(q)+'<span style="font-size:14px">+</span></div>'
      +'<div class="faq-a">'+_esc(a)+'</div></div>';
  }).join("");
  el.classList.add("on");
}
function _openRefund(){
  var el=document.getElementById("refund-ov"),cnt=document.getElementById("refund-content");
  if(!el||!cnt)return;
  cnt.innerHTML="${_esc(s.refundPolicy||"لا توجد سياسة ارجاع محددة")}".replace(/\n/g,"<br>");
  el.classList.add("on");
}

// ── Cart ──
function openCart(){
  document.getElementById("cart-sb").classList.add("on");
  document.getElementById("cart-ov").classList.add("on");
  _renderCart();
}
function closeCart(){
  document.getElementById("cart-sb").classList.remove("on");
  document.getElementById("cart-ov").classList.remove("on");
}
function _renderCart(){
  var el=document.getElementById("cart-items"),ft=document.getElementById("cart-ft"),cb=document.getElementById("cart-count");
  var tot=_cart.reduce(function(a,c){return a+c.price*c.qty;},0);
  var count=_cart.reduce(function(a,c){return a+c.qty;},0);
  if(cb)cb.textContent=count;
  if(!el)return;
  if(!_cart.length){
    el.innerHTML='<div class="c-empty"><span style="font-size:24px;color:rgba(168,85,247,.25);font-family:Georgia,serif;letter-spacing:2px">CART</span><span>السلة فارغة</span></div>';
    if(ft)ft.style.display="none";return;
  }
  if(ft)ft.style.display="flex";
  var tv=document.getElementById("cart-total-val");if(tv)tv.textContent=_fmtP(tot);
  el.innerHTML=_cart.map(function(c,i){return'<div class="c-item" role="listitem">'
    +'<img class="c-img" src="'+_esc(c.img||"")+'" alt="" loading="lazy" onerror="this.style.display=\'none\'">'
    +'<div><div class="c-name">'+_esc(c.name)+'</div><div class="c-price">'+_fmtP(c.price)+'</div>'
    +(c.size?'<div class="c-sz">'+_esc(c.size)+'</div>':"")
    +(c.color?'<div class="c-sz">'+_esc(c.color)+'</div>':"")
    +'</div>'
    +'<button class="rmbtn" onclick="WOW._removeCart('+i+')" aria-label="حذف من السلة">&#10005;</button>'
    +'</div>';}).join("");
}
function _removeCart(i){_cart.splice(i,1);_renderCart();}
function confirmAdd(){
  var p=_currentProd;if(!p)return;
  if(p.sizes&&p.sizes.length&&!_selectedSize){_toast("اختر المقاس");return;}
  if(p.colors&&p.colors.length&&!_selectedColor){_toast("اختر اللون");return;}
  var qi=document.getElementById("mod-qty"),qty=Math.max(1,Math.min(99,parseInt(qi?qi.value:1)||1));
  var effDisc=p.flashDisc||p.discount||0,effPrice=effDisc>0?Math.round(p.price*(1-effDisc/100)):p.price;
  var ex=_cart.findIndex(function(c){return c.id===p.id&&c.size===(_selectedSize||"")&&c.color===(_selectedColor||"");});
  if(ex>=0)_cart[ex].qty=Math.min(99,_cart[ex].qty+qty);
  else _cart.push({id:p.id,name:p.name,price:effPrice,qty:qty,size:_selectedSize||"",color:_selectedColor||"",img:(p.images&&p.images[0])||""});
  _renderCart();_closeMod();_toast("تم الاضافة");
  fetch("/api/products/track",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:p.id,event:"cart"})}).catch(function(){});
  var cb=document.getElementById("cart-count");if(cb){cb.style.transform="scale(1.7)";setTimeout(function(){cb.style.transform="";},320);}
}

// ── Checkout ──
var _chkStep=0;
var SF_CLI=${sfJSON};
function openCheckout(){if(!_cart.length){_toast("السلة فارغة");return;}_chkStep=0;_setChkStep(0);document.getElementById("chk-ov").classList.add("on");closeCart();}
function closeChk(){document.getElementById("chk-ov").classList.remove("on");}
function _setChkStep(n){
  _chkStep=n;
  document.querySelectorAll(".chk-step").forEach(function(s,i){s.classList.toggle("active",i===n);});
  document.querySelectorAll(".step-item").forEach(function(s,i){s.classList.remove("active","done");if(i<n)s.classList.add("done");else if(i===n)s.classList.add("active");});
  if(n===3)_buildChkSummary();
  // CCP field toggle on step 2
  if(n===2){
    document.querySelectorAll("input[name='pay-method']").forEach(function(r){
      r.onchange=function(){
        var f=document.getElementById("ccp-ref-field");if(f)f.style.display=this.value==="ccp"?"block":"none";
        updPreview();
      };
    });
  }
}
function chkNext(n){
  if(n===0){
    var nm=(document.getElementById("b-name")||{}).value||"";
    var p1=((document.getElementById("b-phone1")||{}).value||"").replace(/\s/g,"");
    var p2=((document.getElementById("b-phone2")||{}).value||"").replace(/\s/g,"");
    if(!nm.trim()){_toast("ادخل الاسم");return;}
    if(!/^0[567]\d{8}$/.test(p1)){_toast("الهاتف 1 غير صالح");return;}
    if(!/^0[567]\d{8}$/.test(p2)){_toast("الهاتف 2 غير صالح");return;}
    if(p1===p2){_toast("يجب ان يختلف رقما الهاتف");return;}
  }
  if(n===1){
    var wl=(document.getElementById("b-wilaya")||{}).value||"";
    var cm=((document.getElementById("b-commune")||{}).value||"").trim();
    if(!wl){_toast("اختر الولاية");return;}
    if(!cm){_toast("ادخل البلدية");return;}
  }
  _setChkStep(n+1);
}
function chkPrev(n){_setChkStep(n-1);}
function updPreview(){
  var wl=(document.getElementById("b-wilaya")||{}).value||"";
  var dlbl=(document.getElementById("b-dlbl")||{}).value||"";
  var pay=(document.querySelector("input[name='pay-method']:checked")||{}).value||"cod";
  var isHome=dlbl.includes("منزل");
  var row=SF_CLI[wl]||{h:1100,d:700};
  var fee=isHome?row.h:row.d;
  var sub=_cart.reduce(function(a,c){return a+c.price*c.qty;},0);
  var cpD=_couponApplied?_couponApplied.discAmt:0,ccpD=pay==="ccp"?50:0;
  var tot=sub+fee-cpD-ccpD;
  var pr=document.getElementById("ord-preview");if(pr)pr.style.display="block";
  var set=function(id,v){var el=document.getElementById(id);if(el)el.textContent=v;};
  set("op-sub",_fmtP(sub));set("op-fee",_fmtP(fee));set("op-total",_fmtP(tot));
  var dr=document.getElementById("op-disc-row"),dv=document.getElementById("op-disc");
  if(cpD+ccpD>0){if(dv)dv.textContent="- "+_fmtP(cpD+ccpD);if(dr)dr.style.display="flex";}
  else{if(dr)dr.style.display="none";}
}
function _buildChkSummary(){
  var el=document.getElementById("chk-summary");if(!el)return;
  var V=function(id){return((document.getElementById(id)||{}).value||"");};
  var nm=V("b-name"),p1=V("b-phone1"),p2=V("b-phone2"),wl=V("b-wilaya"),cm=V("b-commune"),dlbl=V("b-dlbl");
  var pay=(document.querySelector("input[name='pay-method']:checked")||{}).value||"cod";
  var row=SF_CLI[wl]||{h:1100,d:700},isHome=dlbl.includes("منزل"),fee=isHome?row.h:row.d;
  var sub=_cart.reduce(function(a,c){return a+c.price*c.qty;},0);
  var cpD=_couponApplied?_couponApplied.discAmt:0,ccpD=pay==="ccp"?50:0;
  el.innerHTML='<div class="op-row"><span class="op-l">العميل</span><span class="op-v">'+_esc(nm)+'</span></div>'
    +'<div class="op-row"><span class="op-l">الهاتف</span><span class="op-v">'+_esc(p1)+" / "+_esc(p2)+'</span></div>'
    +'<div class="op-row"><span class="op-l">الولاية</span><span class="op-v">'+_esc(wl)+" — "+_esc(cm)+'</span></div>'
    +'<div class="op-row"><span class="op-l">التوصيل</span><span class="op-v">'+_esc(dlbl)+'</span></div>'
    +'<div class="op-row"><span class="op-l">المنتجات</span><span class="op-v">'+_fmtP(sub)+'</span></div>'
    +(cpD?'<div class="op-row" style="color:rgba(74,222,128,.8)"><span class="op-l">خصم الكوبون</span><span class="op-v">- '+_fmtP(cpD)+'</span></div>':"")
    +'<div class="op-row"><span class="op-l">الشحن</span><span class="op-v">'+_fmtP(fee)+'</span></div>'
    +(ccpD?'<div class="op-row" style="color:rgba(74,222,128,.8)"><span class="op-l">خصم CCP</span><span class="op-v">- '+_fmtP(ccpD)+'</span></div>':"")
    +'<div class="op-tot"><span class="op-tl">TOTAL</span><span class="op-tv">'+_fmtP(sub+fee-cpD-ccpD)+'</span></div>';
}

// ── م5: Coupon Ajax ──
function _applyCoupon(){
  var code=(document.getElementById("coupon-inp")||{}).value||"";
  var msg=document.getElementById("coupon-msg");if(!code.trim()){if(msg)msg.textContent="ادخل الكود";return;}
  var sub=_cart.reduce(function(a,c){return a+c.price*c.qty;},0);
  var wl=(document.getElementById("b-wilaya")||{}).value||"";
  fetch("/api/coupon-check",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({code:code.trim(),sub:sub,wilaya:wl})})
  .then(function(r){return r.json();}).then(function(d){
    if(msg){msg.textContent=d.msg||"";msg.style.color=d.ok?"rgba(74,222,128,.8)":"rgba(252,165,165,.7)";}
    if(d.ok){_couponApplied=d;updPreview();}else _couponApplied=null;
  }).catch(function(){if(msg)msg.textContent="خطأ في الاتصال";});
}

// ── Submit Order ──
function submitOrder(){
  var btn=document.getElementById("submit-btn");if(btn){btn.disabled=true;btn.textContent="جارٍ الارسال...";}
  var V=function(id){return((document.getElementById(id)||{}).value||"");};
  var payload={
    name:V("b-name").trim(),phone1:V("b-phone1").replace(/\s/g,""),phone2:V("b-phone2").replace(/\s/g,""),
    email:V("b-email").trim(),wilaya:V("b-wilaya"),commune:V("b-commune").trim(),
    dlbl:V("b-dlbl"),payMethod:(document.querySelector("input[name='pay-method']:checked")||{}).value||"cod",
    ccpRef:V("b-ccp-ref").trim(),note:V("b-note").trim(),
    items:_cart.map(function(c){return{id:c.id,qty:c.qty,size:c.size||"",img:c.img||""};}),
  };
  if(_couponApplied)payload.couponCode=_couponApplied.code;
  try{var ref=localStorage.getItem("wow_ref");if(ref)payload.refCode=ref;}catch(e){}
  _api("/api/orders",{method:"POST",body:JSON.stringify(payload)}).then(function(d){
    if(btn){btn.disabled=false;btn.textContent="تاكيد الطلب";}
    if(d.ok){
      var prevCart=[..._cart];
      _cart.forEach(function(c){fetch("/api/products/track",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:c.id,event:"purchase"})}).catch(function(){});});
      _cart=[];_renderCart();_couponApplied=null;closeChk();
      _showInvoice(d,prevCart,payload);
      if(d.repeated)setTimeout(function(){_toast("ملاحظة: هذا الهاتف سبق استخدامه في طلبية");},2500);
    }else _toast(d.error||"حدث خطأ");
  }).catch(function(e){if(btn){btn.disabled=false;btn.textContent="تاكيد الطلب";}_toast((e&&e.error)||"خطأ في الاتصال");});
}

// ── Invoice Mini ──
function _showInvoice(d,cart,payload){
  var ov=document.getElementById("inv-ov"),box=document.getElementById("inv-box");if(!ov||!box)return;
  var sub=cart.reduce(function(a,c){return a+c.price*c.qty;},0);
  box.innerHTML='<div class="inv-brand">${_esc(sn)}</div>'
    +'<div class="inv-sub">ORDER CONFIRMED</div>'
    +'<div class="inv-grid">'
    +'<div class="inv-f"><small>رقم الطلبية</small><span>'+_esc(d.orderId)+'</span></div>'
    +'<div class="inv-f"><small>الاسم</small><span>'+_esc(payload.name||"")+'</span></div>'
    +'<div class="inv-f"><small>الولاية</small><span>'+_esc(payload.wilaya||"")+'</span></div>'
    +'<div class="inv-f"><small>الطريقة</small><span>'+(payload.payMethod==="ccp"?"CCP":"الدفع عند الاستلام")+'</span></div>'
    +'</div>'
    +cart.map(function(c){return'<div class="inv-item"><span>'+_esc(c.name)+(c.size?" ["+_esc(c.size)+"]":"")+" ×"+c.qty+'</span><span>'+_fmtP(c.price*c.qty)+'</span></div>';}).join("")
    +'<div class="inv-tots">'
    +'<div class="inv-row"><span>المنتجات</span><span>'+_fmtP(sub)+'</span></div>'
    +(d.discAmt>0?'<div class="inv-row" style="color:rgba(74,222,128,.8)"><span>الخصم</span><span>- '+_fmtP(d.discAmt)+'</span></div>':"")
    +(d.couponDisc>0?'<div class="inv-row" style="color:rgba(74,222,128,.8)"><span>كوبون</span><span>- '+_fmtP(d.couponDisc)+'</span></div>':"")
    +'<div class="inv-row"><span>الشحن</span><span>'+_fmtP(d.fee)+'</span></div>'
    +(d.ccpDisc>0?'<div class="inv-row" style="color:rgba(74,222,128,.8)"><span>خصم CCP</span><span>- '+_fmtP(d.ccpDisc)+'</span></div>':"")
    +'<div class="inv-final"><span style="font-size:12px;color:#888">TOTAL</span><span class="inv-total">'+_fmtP(d.total)+'</span></div>'
    +'</div>'
    +'<button class="btn-main" style="background:#111;color:#fff;margin-top:12px" onclick="document.getElementById(\'inv-ov\').classList.remove(\'on\')">حسناً</button>'
    +'<button class="btn-main" style="background:rgba(0,0,0,.06);color:#333;border:1px solid #ddd;margin-top:8px" onclick="window.open(\'/invoice?id='+_esc(d.orderId)+'\',\'_blank\')">فتح الفاتورة</button>';
  ov.classList.add("on");
}

// ── Track Order ──
function doTrack(){
  var inp=(document.getElementById("track-inp")||{}).value||"";
  var res=document.getElementById("track-result");if(!res)return;
  if(!inp.trim()){res.innerHTML='<div style="color:var(--mu);font-size:11px">ادخل رقم الطلبية او الهاتف</div>';return;}
  res.innerHTML='<div style="color:var(--mu);font-size:11px">جارٍ البحث...</div>';
  fetch("/api/track",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({orderId:inp.trim(),phone:inp.trim()})})
  .then(function(r){return r.json();}).then(function(d){
    if(!d.ok){res.innerHTML='<div style="color:rgba(252,165,165,.7);font-size:11px">لم يتم العثور على هذه الطلبية</div>';return;}
    var SC={processing:"#f59e0b",shipped:"#3b82f6",delivered:"#22c55e",returned:"#ef4444"};
    var STL={processing:"قيد المعالجة",shipped:"تم الشحن",delivered:"تم التوصيل",returned:"مرتجعة"};
    var c=SC[d.status]||"#a855f7";
    res.innerHTML='<div style="background:rgba(255,255,255,.03);border:1px solid rgba(168,85,247,.15);border-radius:12px;padding:14px;text-align:center">'
      +'<div style="font-size:10px;color:var(--mu);margin-bottom:8px;font-family:monospace">'+_esc(d.id)+'</div>'
      +'<div style="display:inline-block;padding:4px 14px;border-radius:12px;font-size:12px;font-weight:700;background:'+c+'22;color:'+c+'">'+_esc(STL[d.status]||d.status)+'</div>'
      +'<div style="font-size:11px;color:var(--dim);margin-top:10px">'+_esc(d.name||"")+" — "+_esc(d.wilaya||"")+'</div>'
      +'</div>';
  }).catch(function(){res.innerHTML='<div style="color:rgba(252,165,165,.7);font-size:11px">خطأ في الاتصال</div>';});
}

// ── Admin Orders ──
function _loadOrders(){
  _api("/api/orders").then(function(orders){_ordersCache=orders||[];_filterOrders();_checkDuplicates();}).catch(function(){});
}
function _checkDuplicates(){
  var dups=_ordersCache.filter(function(o){return o.repeated;});
  var wrap=document.getElementById("alert-duplicates"),list=document.getElementById("alert-dup-list");
  if(!wrap||!list)return;
  if(dups.length){wrap.style.display="block";list.innerHTML=dups.slice(0,5).map(function(o){return'<div>'+_esc(o.id)+" — "+_esc(o.name||"")+" ("+_esc(o.phone1||"")+')</div>';}).join("");}
  else wrap.style.display="none";
}

// ── م8: Multi-filter ──
function _filterOrders(){
  var sch=((document.getElementById("ord-search")||{}).value||"").toLowerCase();
  var sta=(document.getElementById("ord-flt-status")||{}).value||"";
  var wil=(document.getElementById("ord-flt-wilaya")||{}).value||"";
  var conf=(document.getElementById("ord-flt-confirmed")||{}).value||"";
  try{
    var sp=new URLSearchParams;
    if(sch)sp.set("s",sch);if(sta)sp.set("st",sta);if(wil)sp.set("w",wil);if(conf)sp.set("c",conf);
    history.replaceState(null,"",sp.toString()?"?"+sp.toString():location.pathname);
  }catch(e){}
  _renderOrders(_ordersCache.filter(function(o){
    if(sch&&!(o.name||"").toLowerCase().includes(sch)&&!(o.phone1||"").includes(sch)&&!(o.id||"").toLowerCase().includes(sch)&&!(o.wilaya||"").includes(sch))return false;
    if(sta&&o.status!==sta)return false;
    if(wil&&o.wilaya!==wil)return false;
    if(conf==="1"&&!o.confirmed)return false;
    if(conf==="0"&&o.confirmed)return false;
    return true;
  }));
}

// ── Render Orders ──
function _renderOrders(orders){
  var el=document.getElementById("ord-list");if(!el)return;
  if(!orders.length){el.innerHTML='<div style="text-align:center;padding:30px;color:var(--mu);font-size:12px">لا توجد طلبيات</div>';return;}
  var SC={processing:"#f59e0b",shipped:"#3b82f6",delivered:"#22c55e",returned:"#ef4444"};
  var STL={processing:"قيد المعالجة",shipped:"تم الشحن",delivered:"تم التوصيل",returned:"مرتجعة"};
  el.innerHTML=orders.map(function(o){
    var c=SC[o.status]||"#a855f7";
    var savedNote="";try{savedNote=localStorage.getItem("wow_note_"+o.id)||"";}catch(e){}
    var noteVal=o.note||savedNote;
    return'<div class="ord-row'+(o.repeated?" repeated":"")+'"><div class="ord-hdr" onclick="WOW._toggleOrder(\'od-'+_esc(o.id)+'\')">'
      +'<div><div style="display:flex;align-items:center;gap:6px">'
      +'<input type="checkbox" class="ord-chk" data-id="'+_esc(o.id)+'" onclick="event.stopPropagation();WOW._toggleBulk(\''+_esc(o.id)+'\')" style="accent-color:#a855f7;width:15px;height:15px;cursor:pointer;flex-shrink:0">'
      +'<span class="ord-id">'+_esc(o.id)+'</span>'
      +(o.repeated?'<span style="font-size:9px;color:rgba(252,165,165,.7);border:1px solid rgba(239,68,68,.3);padding:1px 5px;border-radius:3px">مكرر</span>':"")
      +'</div>'
      +'<div class="ord-name">'+_esc(o.name||"")+'</div>'
      +'<div class="ord-meta">'+_esc(o.wilaya||"")+" — "+_esc(o.phone1||"")+" | "+_fmtP(o.total||0)+'</div></div>'
      +'<span class="ord-badge" style="background:'+c+'22;color:'+c+'">'+_esc(STL[o.status]||o.status||"")+'</span>'
      +'</div>'
      +'<div class="ord-body" id="od-'+_esc(o.id)+'">'
      +'<div class="ord-det">'
      +'الهاتف: '+_esc(o.phone1||"")+(o.phone2?" / "+_esc(o.phone2):"")+'<br>'
      +'البلدية: '+_esc(o.commune||"")+'<br>'
      +'التوصيل: '+_esc(o.dlbl||"")+'<br>'
      +'الدفع: '+(o.payMethod==="ccp"?"CCP":"عند الاستلام")
      +(o.ccpRef?'<br>وصل CCP: '+_esc(o.ccpRef):"")+'<br>'
      +(o.note?'ملاحظة: '+_esc(o.note)+'<br>':"")
      +'المنتجات:<br>'+(o.items||[]).map(function(it){return _esc(it.name||"")+(it.size?" ["+_esc(it.size)+"]":"")+" ×"+it.qty+" = "+_fmtP((it.price||0)*it.qty);}).join("<br>")
      +(o.history&&o.history.length?'<br><br>السجل:<br>'+o.history.map(function(h){return'<span style="color:rgba(168,85,247,.4)">'+_esc((h.t||"").substring(0,16))+'</span> '+_esc(h.txt||"");}).join("<br>"):"")
      +(o.auditTrail&&o.auditTrail.length?'<br><br><strong>Audit Trail:</strong><br>'+o.auditTrail.slice(0,4).map(function(a){return'<div class="audit-row"><span class="audit-ts">'+_esc((a.t||"").substring(0,16))+'</span><span class="audit-type">'+_esc(a.type||"")+'</span><span>'+_esc(a.actor||"")+'</span></div>';}).join(""):"")
      +'</div>'
      +'<div class="ord-acts">'
      +'<button class="aibtn" onclick="WOW._confOrd(\''+_esc(o.id)+'\','+(!o.confirmed)+')">'+(o.confirmed?"الغاء التاكيد":"تاكيد")+'</button>'
      +'<select class="ord-sel" onchange="WOW._updStatus(\''+_esc(o.id)+'\',this.value)">'
      +'<option value="">الحالة</option>'
      +'<option value="processing">قيد المعالجة</option>'
      +'<option value="shipped">تم الشحن</option>'
      +'<option value="delivered">تم التوصيل</option>'
      +'<option value="returned">مرتجعة</option>'
      +'</select>'
      +'<div style="width:100%;margin-top:6px">'
      +'<textarea class="note-ta" placeholder="ملاحظة داخلية..." oninput="WOW._debouncedNote(\''+_esc(o.id)+'\',this)">'+_esc(noteVal)+'</textarea>'
      +'<div class="note-saved-indicator" id="ni-'+_esc(o.id)+'">تم الحفظ</div>'
      +'</div>'
      +'<button class="aibtn" onclick="window.open(\'/invoice?id='+_esc(o.id)+'\',\'_blank\')">فاتورة</button>'
      +'<button class="aibtn" onclick="window.open(\'/shipping-label?id='+_esc(o.id)+'\',\'_blank\')">بوليصة</button>'
      +'<button class="aibtn del" onclick="WOW._delOrder(\''+_esc(o.id)+'\')">&#10005;</button>'
      +'</div></div></div>';
  }).join("");
  _bulkSelected.forEach(function(id){var c=el.querySelector('input[data-id="'+id+'"]');if(c)c.checked=true;});
}

function _toggleOrder(id){var el=document.getElementById(id);if(el)el.classList.toggle("on");}
function _confOrd(id,val){_api("/api/orders",{method:"PATCH",body:JSON.stringify({id:id,confirmed:val})}).then(function(){_loadOrders();_toast(val?"تم التاكيد":"تم الالغاء");}).catch(function(){_toast("خطأ");});}
function _updStatus(id,status){if(!status)return;_api("/api/orders",{method:"PATCH",body:JSON.stringify({id:id,status:status})}).then(function(){_loadOrders();_toast("تم التحديث");}).catch(function(){_toast("خطأ");});}

// ── م9: Notes Debounce ──
function _debouncedNote(id,el){
  try{localStorage.setItem("wow_note_"+id,el.value);}catch(e){}
  clearTimeout(_noteDebounce[id]);
  _noteDebounce[id]=setTimeout(function(){
    _api("/api/orders",{method:"PATCH",body:JSON.stringify({id:id,note:el.value})})
    .then(function(){var ni=document.getElementById("ni-"+id);if(ni){ni.style.display="block";setTimeout(function(){ni.style.display="none";},2000);}})
    .catch(function(){_toast("تم الحفظ محلياً");});
  },1000);
}

// ── م3: Confirm Delete ──
function _showConfirmDel(title,meta,onConfirm){
  _cdCallback=onConfirm;
  var ov=document.getElementById("confirm-del-ov");
  if(!ov)return;
  document.getElementById("cd-title").textContent=title||"تاكيد الحذف";
  document.getElementById("cd-meta").textContent=meta||"";
  var inp=document.getElementById("cd-input"),ok=document.getElementById("cd-ok-btn"),fill=document.getElementById("cd-hold-fill");
  inp.value="";ok.disabled=true;if(fill)fill.style.width="0";
  ov.classList.add("on");
  setTimeout(function(){inp.focus();},150);
  if(_cdHoldInterval)clearInterval(_cdHoldInterval);
  if(_cdHoldTimer)clearTimeout(_cdHoldTimer);
}
function _initConfirmDel(){
  var inp=document.getElementById("cd-input"),ok=document.getElementById("cd-ok-btn"),fill=document.getElementById("cd-hold-fill");
  var cancel=document.getElementById("cd-cancel-btn"),ov=document.getElementById("confirm-del-ov");
  if(!inp||!ok)return;
  inp.addEventListener("input",function(){
    ok.disabled=this.value.trim()!=="حذف";
  });
  ok.addEventListener("click",function(){
    if(ok.disabled)return;
    if(_cdCallback){_cdCallback();_cdCallback=null;}
    ov.classList.remove("on");
  });
  // Hold for 2s on mobile
  var holdT=0;
  ok.addEventListener("touchstart",function(e){
    if(fill)fill.style.transition="width 2s linear",fill.style.width="100%";
    holdT=setTimeout(function(){
      if(_cdCallback){_cdCallback();_cdCallback=null;}
      ov.classList.remove("on");
      if(fill){fill.style.width="0";fill.style.transition="none";}
    },2000);
  },{passive:true});
  ok.addEventListener("touchend",function(){
    clearTimeout(holdT);
    if(fill){fill.style.width="0";fill.style.transition="none";}
  });
  if(cancel)cancel.addEventListener("click",function(){ov.classList.remove("on");if(_cdCallback)_cdCallback=null;});
}

// ── Delete helpers ──
function _delOrder(id){
  var o=_ordersCache.find(function(x){return x.id===id;});
  _showConfirmDel("حذف الطلبية",id+(o?" — "+_esc(o.name||""):""),function(){
    _api("/api/orders?id="+encodeURIComponent(id),{method:"DELETE"}).then(function(){_loadOrders();_toast("تم الحذف");}).catch(function(){_toast("خطأ");});
  });
}
function _clearOrders(){
  _showConfirmDel("مسح كل الطلبيات","لا يمكن التراجع",function(){
    _api("/api/orders",{method:"DELETE"}).then(function(){_ordersCache=[];_filterOrders();_toast("تم المسح");}).catch(function(){_toast("خطأ");});
  });
}

// ── م10: Group by Wilaya ──
function _groupOrders(){
  var el=document.getElementById("ord-list");if(!el)return;
  var groups={};
  _ordersCache.forEach(function(o){var w=o.wilaya||"غير محددة";if(!groups[w])groups[w]=[];groups[w].push(o);});
  el.innerHTML=Object.entries(groups).sort(function(a,b){return b[1].length-a[1].length;}).map(function(entry){
    var w=entry[0],ords=entry[1],total=ords.reduce(function(a,o){return a+(o.total||0);},0);
    return'<div class="wilaya-group"><div class="wilaya-group-hdr" onclick="this.nextElementSibling.classList.toggle(\'on\')">'
      +'<span class="wilaya-group-title">'+_esc(w)+'</span>'
      +'<span class="wilaya-group-meta">'+ords.length+" طلب — "+_fmtP(total)+'</span></div>'
      +'<div class="wilaya-group-body">'+ords.map(function(o){return'<div style="font-size:11px;color:var(--dim);padding:5px 0;border-bottom:1px solid rgba(255,255,255,.04)">'+_esc(o.id)+" — "+_esc(o.name||"")+" — "+_fmtP(o.total||0)+'</div>';}).join("")+'</div></div>';
  }).join("");
}

// ── م7: CSV Export ──
function _exportCSV(){
  var el=document.getElementById("csv-col-chooser");if(!el)return;
  el.style.display=el.style.display==="none"||!el.style.display?"block":"none";
  var cols=["id","date","name","phone1","phone2","wilaya","commune","dlbl","payMethod","total","status","confirmed","note"];
  var cc=document.getElementById("csv-cols");
  if(cc&&!cc.children.length){cc.innerHTML=cols.map(function(c){return'<label style="display:flex;align-items:center;gap:4px;font-size:11px;color:var(--mu);cursor:pointer"><input type="checkbox" checked value="'+c+'" style="accent-color:#a855f7"> '+c+'</label>';}).join("");}
}
function _doExportCSV(){
  var chosen=[];document.querySelectorAll("#csv-cols input:checked").forEach(function(c){chosen.push(c.value);});
  if(!chosen.length){_toast("اختر الاعمدة");return;}
  var BOM="\uFEFF",rows=[chosen.join(",")].concat(_ordersCache.map(function(o){return chosen.map(function(col){var v=String(o[col]!=null?o[col]:"");return'"'+v.replace(/"/g,'""')+'"';}).join(",");}));
  var blob=new Blob([BOM+rows.join("\r\n")],{type:"text/csv;charset=utf-8"});
  var a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="wow-orders-"+new Date().toISOString().slice(0,10)+".csv";a.click();URL.revokeObjectURL(a.href);
  var el=document.getElementById("csv-col-chooser");if(el)el.style.display="none";_toast("تم التصدير");
}

// ── م13: Bulk Select ──
function _toggleBulk(id){
  if(_bulkSelected.has(id))_bulkSelected.delete(id);else _bulkSelected.add(id);
  var bar=document.getElementById("bulk-bar"),cnt=document.getElementById("bulk-count");
  if(bar)bar.classList.toggle("on",_bulkSelected.size>0);
  if(cnt)cnt.textContent=_bulkSelected.size+" محدد";
}
function _clearBulk(){
  _bulkSelected.clear();document.querySelectorAll(".ord-chk").forEach(function(c){c.checked=false;});
  var bar=document.getElementById("bulk-bar");if(bar)bar.classList.remove("on");
}
function _bulkPrint(){
  if(!_bulkSelected.size){_toast("حدد طلبيات");return;}
  fetch("/api/bulk-print",{method:"POST",headers:{"Content-Type":"application/json","X-Admin-Key":_adminToken||""},body:JSON.stringify({ids:Array.from(_bulkSelected)})})
  .then(function(r){return r.text();}).then(function(html){var w=window.open("","_blank");if(w){w.document.write(html);w.document.close();}}).catch(function(){_toast("خطأ في الطباعة");});
}
function _bulkConfirm(val){
  var ids=Array.from(_bulkSelected);if(!ids.length){_toast("حدد طلبيات");return;}
  Promise.all(ids.map(function(id){return _api("/api/orders",{method:"PATCH",body:JSON.stringify({id:id,confirmed:val})});}))
  .then(function(){_loadOrders();_clearBulk();_toast("تم");}).catch(function(){_toast("خطأ");});
}
function _bulkStatus(status){
  var ids=Array.from(_bulkSelected);if(!ids.length){_toast("حدد طلبيات");return;}
  Promise.all(ids.map(function(id){return _api("/api/orders",{method:"PATCH",body:JSON.stringify({id:id,status:status})});}))
  .then(function(){_loadOrders();_clearBulk();_toast("تم");}).catch(function(){_toast("خطأ");});
}

// ── Admin Products ──
function _renderAdminProds(prods){
  var el=document.getElementById("aprd-list");if(!el)return;
  var lbl=document.getElementById("prod-count-lbl");if(lbl)lbl.textContent="("+prods.length+")";
  if(!prods.length){el.innerHTML='<div style="text-align:center;padding:30px;color:var(--mu);font-size:12px">لا توجد منتجات</div>';return;}
  el.innerHTML=prods.map(function(p){
    var img=p.images&&p.images[0]?p.images[0]:"";
    var isLow=p.quantity!==null&&p.quantity!==undefined&&p.quantity<=(p.alertQty||5);
    var isScheduled=p.showAt&&new Date(p.showAt).getTime()>Date.now();
    return'<div class="aprd-row" draggable="true" data-id="'+p.id+'" id="aprow-'+p.id+'">'
      +'<img class="aprd-img" src="'+_esc(img)+'" alt="" loading="lazy" onerror="this.style.display=\'none\'">'
      +'<div class="aprd-info">'
      +'<div class="aprd-name">'+_esc(p.name||"")+'</div>'
      +'<div class="aprd-price">'+_fmtP(p.price)+(p.discount?" (-"+p.discount+"%)")+"</div>"
      +'<div class="aprd-meta">'+_esc(p.cat||"")+" — "+(p.quantity!==null&&p.quantity!==undefined?p.quantity+" قطعة":"غير محدود")+(isLow?' <span style="color:rgba(252,165,165,.7)">!</span>':"")+'</div>'
      +(isScheduled?'<span class="scheduled-badge">مجدول: '+new Date(p.showAt).toLocaleDateString("ar-DZ")+'</span>':"")
      +'</div>'
      +'<div class="aprd-acts">'
      +'<button class="aibtn" onclick="WOW.editProd('+p.id+')" aria-label="تعديل">&#9998;</button>'
      +'<button class="aibtn" onclick="WOW._archiveProd('+p.id+')">ارشفة</button>'
      +'<button class="aibtn del" onclick="WOW.delProd('+p.id+')" aria-label="حذف">&#10005;</button>'
      +'</div></div>';
  }).join("");
  _initDragDrop(el);
}
function _filterAdminProds(){
  var s=((document.getElementById("aprd-search")||{}).value||"").toLowerCase();
  var cat=(document.getElementById("aprd-cat-flt")||{}).value||"";
  _renderAdminProds(_prods.filter(function(p){
    if(s&&!(p.name||"").toLowerCase().includes(s))return false;
    if(cat&&p.cat!==cat)return false;
    return true;
  }));
}

// ── م43: Drag & Drop ──
function _initDragDrop(container){
  container.querySelectorAll(".aprd-row[draggable]").forEach(function(row){
    row.addEventListener("dragstart",function(e){_dragSrc=row;row.classList.add("dragging");e.dataTransfer.effectAllowed="move";});
    row.addEventListener("dragend",function(){row.classList.remove("dragging","drag-over");});
    row.addEventListener("dragover",function(e){e.preventDefault();e.dataTransfer.dropEffect="move";row.classList.add("drag-over");});
    row.addEventListener("dragleave",function(){row.classList.remove("drag-over");});
    row.addEventListener("drop",function(e){
      e.preventDefault();row.classList.remove("drag-over");
      if(!_dragSrc||_dragSrc===row)return;
      var p=row.parentNode;
      var rows=Array.from(p.querySelectorAll(".aprd-row"));
      var si=rows.indexOf(_dragSrc),ti=rows.indexOf(row);
      if(si<ti)p.insertBefore(_dragSrc,row.nextSibling);else p.insertBefore(_dragSrc,row);
      var newIds=Array.from(p.querySelectorAll(".aprd-row")).map(function(r){return r.dataset.id;});
      _api("/api/products/reorder",{method:"POST",body:JSON.stringify({ids:newIds})}).then(function(){_toast("تم حفظ الترتيب");}).catch(function(){});
    });
  });
}

// ── Edit/Save Product ──
function _editProd(id){
  var p=_prods.find(function(x){return x.id===id;});if(!p)return;
  _editingId=id;_prodImgs=p.images?[...(p.images)]:[];
  _aTab("addprod",null);
  var tl=document.getElementById("addprod-title");if(tl)tl.textContent="تعديل المنتج";
  var cb=document.getElementById("cancel-edit-btn");if(cb)cb.style.display="flex";
  document.getElementById("edit-id").value=id;
  var S=function(i,v){var el=document.getElementById(i);if(el)el.value=v!==undefined&&v!==null?v:"";};
  S("p-name",p.name||"");S("p-name-en",p.nameEn||"");S("p-name-fr",p.nameFr||"");
  S("p-price",p.price||0);S("p-disc",p.discount||0);S("p-cost",p.costPrice||0);
  S("p-cat",p.cat||"other");S("p-desc",p.desc||"");S("p-desc-en",p.descEn||"");S("p-desc-fr",p.descFr||"");
  S("p-qty",p.quantity!==null&&p.quantity!==undefined?p.quantity:"");
  S("p-alert-qty",p.alertQty||5);
  S("p-sizes",(p.sizes||[]).join(", "));S("p-colors",(p.colors||[]).join(", "));
  if(p.showAt){var dt=new Date(p.showAt);S("p-show-at",dt.toISOString().slice(0,16));}else S("p-show-at","");
  _calcDisc();_renderPreviews();
}
function _cancelEdit(){
  _editingId=null;_prodImgs=[];
  var tl=document.getElementById("addprod-title");if(tl)tl.textContent="اضافة منتج جديد";
  var cb=document.getElementById("cancel-edit-btn");if(cb)cb.style.display="none";
  document.getElementById("edit-id").value="";
  ["p-name","p-name-en","p-name-fr","p-price","p-disc","p-cost","p-desc","p-desc-en","p-desc-fr","p-qty","p-sizes","p-colors","p-show-at"].forEach(function(i){var el=document.getElementById(i);if(el)el.value="";});
  var aq=document.getElementById("p-alert-qty");if(aq)aq.value="5";
  _renderPreviews();
}
function _saveProd(){
  var btn=document.getElementById("save-btn");if(btn){btn.disabled=true;btn.textContent="جارٍ الحفظ...";}
  var G=function(i){return((document.getElementById(i)||{}).value||"");};
  var name=G("p-name").trim();
  if(!name){_toast("ادخل اسم المنتج");if(btn){btn.disabled=false;btn.textContent="حفظ المنتج";}return;}
  var qv=G("p-qty"),qty=qv===""||qv===null?null:Math.max(0,parseInt(qv)||0);
  var showAt=G("p-show-at");
  var payload={
    name:name,nameEn:G("p-name-en").trim(),nameFr:G("p-name-fr").trim(),
    price:Math.max(0,parseFloat(G("p-price"))||0),discount:Math.min(90,Math.max(0,parseInt(G("p-disc"))||0)),
    costPrice:Math.max(0,parseInt(G("p-cost"))||0),cat:G("p-cat")||"other",
    desc:G("p-desc").trim(),descEn:G("p-desc-en").trim(),descFr:G("p-desc-fr").trim(),
    quantity:qty,alertQty:Math.max(0,parseInt(G("p-alert-qty"))||5),
    sizes:G("p-sizes").split(",").map(function(s){return s.trim();}).filter(Boolean),
    colors:G("p-colors").split(",").map(function(c){return c.trim();}).filter(Boolean),
    images:_prodImgs,showAt:showAt||null
  };
  if(_editingId)payload.id=_editingId;
  _api("/api/products",{method:_editingId?"PUT":"POST",body:JSON.stringify(payload)}).then(function(){
    if(btn){btn.disabled=false;btn.textContent="حفظ المنتج";}
    _toast(_editingId?"تم التعديل":"تم الحفظ");_cancelEdit();_loadProds();_aTab("products",null);
  }).catch(function(e){if(btn){btn.disabled=false;btn.textContent="حفظ المنتج";}_toast((e&&e.error)||"خطأ");});
}
function _delProd(id){
  var p=_prods.find(function(x){return x.id===id;});
  _showConfirmDel("حذف المنتج",p?_esc(p.name||""):"ID: "+id,function(){
    _api("/api/products?id="+id,{method:"DELETE"}).then(function(){_loadProds();_toast("تم الحذف");}).catch(function(){_toast("خطأ");});
  });
}
function _archiveProd(id){
  _api("/api/products?id="+id+"&archive=1",{method:"DELETE"}).then(function(){_loadProds();_toast("تم الارشفة");}).catch(function(){_toast("خطأ");});
}

// ── م44: Lang Tabs ──
function _switchLang(lang,el){
  _langActive=lang;
  ["ar","en","fr"].forEach(function(l){
    var b=document.getElementById("lt-"+l);if(b)b.classList.toggle("on",l===lang);
    if(l!=="ar"){
      ["p-name","p-desc"].forEach(function(base){
        var wrap=document.getElementById(base+"-"+l+"-wrap");
        if(wrap)wrap.style.display=l===lang?"block":"none";
      });
    }
  });
}

// ── Images ──
function _handleDrop(e){e.preventDefault();var dz=document.getElementById("drop-zone");if(dz)dz.classList.remove("drag");if(e.dataTransfer)_handleImgs(e.dataTransfer.files);}
function _handleImgs(files){
  if(!files||!files.length)return;
  var max=4-_prodImgs.length;
  Array.from(files).slice(0,max).forEach(function(file){
    if(!file.type.startsWith("image/"))return;
    if(file.size>300000){_toast("الصورة كبيرة جداً — الحد الأقصى 300KB");return;}
    var r=new FileReader();r.onload=function(ev){if(_prodImgs.length<4){_prodImgs.push(ev.target.result);_renderPreviews();}};r.readAsDataURL(file);
  });
}
function _renderPreviews(){
  var el=document.getElementById("img-prev");if(!el)return;
  el.innerHTML=_prodImgs.map(function(src,i){return'<div class="img-prev-item"><img src="'+_esc(src)+'" alt="" loading="lazy"><button class="img-del" onclick="WOW.delImg('+i+')" aria-label="حذف">&#10005;</button></div>';}).join("");
}
function _delImg(i){_prodImgs.splice(i,1);_renderPreviews();}
function _calcDisc(){
  var price=parseFloat((document.getElementById("p-price")||{}).value||0)||0;
  var disc=parseInt((document.getElementById("p-disc")||{}).value||0)||0;
  var hint=document.getElementById("disc-preview");
  if(hint&&price>0&&disc>0){hint.style.display="block";var after=Math.round(price*(1-disc/100));hint.textContent="السعر بعد الخصم: "+_fmtP(after)+" (خصم "+_fmtP(price-after)+")";}
  else if(hint)hint.style.display="none";
}

// ── م5: Coupons ──
function _loadCoupons(){
  _api("/api/coupons").then(function(coupons){
    var el=document.getElementById("cp-list");if(!el)return;
    if(!coupons.length){el.innerHTML='<div style="color:var(--mu);font-size:11px;text-align:center;padding:20px">لا توجد كوبونات</div>';return;}
    el.innerHTML=coupons.map(function(c){return'<div class="cp-row">'
      +'<span class="ord-badge" style="background:rgba(168,85,247,.12);color:rgba(192,132,252,.8)">'+_esc(c.code)+'</span>'
      +'<div style="flex:1"><div style="font-size:11px;color:var(--tx)">'+c.discVal+(c.discType==="percent"?"%":" دج")+'</div>'
      +'<div style="font-size:10px;color:var(--mu)">'+(c.usedCount||0)+"/"+(c.maxUses||"∞")+(c.minSub?" — حد: "+_fmtP(c.minSub):"")+'</div></div>'
      +'<span style="font-size:10px;color:'+(c.active?"rgba(74,222,128,.7)":"rgba(252,165,165,.5)")+'">'+( c.active?"نشط":"معطل")+'</span>'
      +'<button class="aibtn" onclick="WOW._toggleCoupon('+c.id+','+(!c.active)+')">'+(c.active?"تعطيل":"تفعيل")+'</button>'
      +'<button class="aibtn del" onclick="WOW._deleteCoupon('+c.id+')">&#10005;</button>'
      +'</div>';}).join("");
  }).catch(function(){});
}
function _createCoupon(){
  var G=function(i){return((document.getElementById(i)||{}).value||"");};
  var code=G("cp-code").trim(),type=G("cp-type"),val=parseFloat(G("cp-val")),maxuses=parseInt(G("cp-maxuses")||0),expires=G("cp-expires"),minsub=parseInt(G("cp-minsub")||0);
  var wilayas=G("cp-wilayas").split(",").map(function(w){return w.trim();}).filter(Boolean);
  if(!code||!val){_toast("ادخل الكود والقيمة");return;}
  _api("/api/coupons",{method:"POST",body:JSON.stringify({code:code,discType:type,discVal:val,maxUses:maxuses,expiresAt:expires||null,minSub:minsub,wilayas:wilayas})})
  .then(function(){_loadCoupons();_toast("تم انشاء الكوبون");["cp-code","cp-val","cp-maxuses","cp-expires","cp-minsub","cp-wilayas"].forEach(function(i){var el=document.getElementById(i);if(el)el.value="";});})
  .catch(function(e){_toast((e&&e.error)||"خطأ");});
}
function _toggleCoupon(id,active){_api("/api/coupons",{method:"PATCH",body:JSON.stringify({id:id,active:active})}).then(function(){_loadCoupons();}).catch(function(){_toast("خطأ");});}
function _deleteCoupon(id){_showConfirmDel("حذف الكوبون","",function(){_api("/api/coupons?id="+id,{method:"DELETE"}).then(function(){_loadCoupons();_toast("تم");}).catch(function(){_toast("خطأ");});});}

// ── م4: Archive ──
function _loadArchive(){
  var cat=(document.getElementById("arch-cat-flt")||{}).value||"";
  _api("/api/products/archive"+(cat?"?cat="+encodeURIComponent(cat):"")).then(function(arch){
    var el=document.getElementById("arch-list");if(!el)return;
    if(!arch.length){el.innerHTML='<div style="color:var(--mu);font-size:11px;text-align:center;padding:20px">الارشيف فارغ</div>';return;}
    el.innerHTML=arch.map(function(p){return'<div class="aprd-row" id="archrow-'+p.id+'">'
      +'<div style="display:flex;align-items:center;gap:8px;min-width:0">'
      +'<input type="checkbox" class="arch-chk" data-id="'+p.id+'" onclick="WOW._toggleArchSel(\''+p.id+'\')" style="accent-color:#a855f7;width:15px;height:15px;cursor:pointer;flex-shrink:0">'
      +'<img class="aprd-img" src="'+_esc((p.images&&p.images[0])||"")+'" alt="" loading="lazy" style="flex-shrink:0">'
      +'</div>'
      +'<div class="aprd-info"><div class="aprd-name">'+_esc(p.name||"")+'</div><div class="aprd-price">'+_fmtP(p.price||0)+'</div><div class="aprd-meta">'+new Date(p.archivedAt||"").toLocaleDateString("ar-DZ")+'</div></div>'
      +'<div class="aprd-acts"><button class="aibtn" onclick="WOW._restoreProd('+p.id+')">استعادة</button></div>'
      +'</div>';}).join("");
  }).catch(function(){});
}
function _toggleArchSel(id){id=String(id);if(_archSelected.has(id))_archSelected.delete(id);else _archSelected.add(id);}
function _archSelectAll(){_archSelected.clear();document.querySelectorAll(".arch-chk").forEach(function(c){c.checked=true;_archSelected.add(String(c.dataset.id));});}
function _restoreProd(id){_api("/api/products/archive",{method:"POST",body:JSON.stringify({action:"restore",id:id})}).then(function(){_loadArchive();_loadProds();_toast("تم الاستعادة");}).catch(function(){_toast("خطأ");});}
function _bulkRestore(){
  if(!_archSelected.size){_toast("حدد منتجات");return;}
  _api("/api/products/archive",{method:"POST",body:JSON.stringify({action:"bulk_restore",ids:Array.from(_archSelected)})})
  .then(function(d){_loadArchive();_loadProds();_archSelected.clear();_toast("تم استعادة "+(d.count||0)+" منتج");}).catch(function(){_toast("خطأ");});
}

// ── م15+م16+م37: Analytics ──
function _loadAnalytics(){
  _api("/api/analytics").then(function(d){
    var el=document.getElementById("analytics-kpis");
    if(el)el.innerHTML=[
      {l:"اجمالي الزيارات",v:d.totalVisits||0},{l:"زوار فريدون",v:d.uniqueVisitors||0},
      {l:"نسبة التاكيد",v:(d.confirmRate||0)+"%"},{l:"متوسط الطلب",v:_fmtP(d.avgOrderVal||0)},
      {l:"معدل الارتداد",v:(d.bounceRate||0)+"%"},{l:"هذا الاسبوع",v:_fmtP(d.revThisWeek||0)},
      {l:"هذا الشهر",v:_fmtP(d.revThisMonth||0)},{l:"الايراد الكلي",v:_fmtP(d.revenue||0)},
    ].map(function(k){return'<div class="kpi-card"><div class="kpi-label">'+_esc(k.l)+'</div><div class="kpi-val">'+k.v+'</div></div>';}).join("");
    // م37
    var pe=document.getElementById("profit-kpis");
    if(pe&&d.grossProfit!==undefined)pe.innerHTML=[
      {l:"الايراد الصافي",v:_fmtP(d.netRevenue||0)},
      {l:"اجمالي التكلفة",v:_fmtP(d.totalCost||0)},
      {l:"صافي الربح",v:_fmtP(d.grossProfit||0),c:d.grossProfit>0?"kpi-good":"kpi-bad"},
      {l:"هامش الربح",v:(d.profitMargin||0)+"%",c:d.profitMargin>20?"kpi-good":"kpi-bad"},
    ].map(function(k){return'<div class="kpi-card"><div class="kpi-label">'+_esc(k.l)+'</div><div class="kpi-val '+( k.c||"")+'">'+k.v+'</div></div>';}).join("");
    _drawChart(d.dailySales,"revenue-chart");
    _renderWilayaHeat(d.wilayaMap||{});
    _renderDeviceReport(d);
  }).catch(function(){});
}
function _renderWilayaHeat(wm){
  var el=document.getElementById("wilaya-heat-list");if(!el)return;
  var entries=Object.entries(wm).sort(function(a,b){return b[1]-a[1];}).slice(0,20);
  if(!entries.length){el.innerHTML='<div style="color:var(--mu);font-size:11px">لا توجد بيانات</div>';return;}
  var max=entries[0][1]||1;
  el.innerHTML=entries.map(function(e){var pct=Math.round(e[1]/max*100);return'<div class="dev-bar"><span class="dev-bar-label">'+_esc(e[0])+'</span><div style="flex:1;height:5px;background:rgba(255,255,255,.04);border-radius:3px;overflow:hidden"><div class="dev-bar-fill" style="width:'+pct+'%"></div></div><span class="dev-bar-val">'+e[1]+'</span></div>';}).join("");
}
function _renderDeviceReport(d){
  var el=document.getElementById("device-report");if(!el)return;
  var bm={};(d.visitors||[]).forEach(function(v){if(v.browser)bm[v.browser]=(bm[v.browser]||0)+1;});
  var secs=[{t:"الانظمة",m:d.osMap||{}},{t:"المتصفحات",m:bm},{t:"الفئات",m:d.tierMap||{}}];
  el.innerHTML=secs.map(function(sec){
    var entries=Object.entries(sec.m).sort(function(a,b){return b[1]-a[1];}).slice(0,6);
    var tot=entries.reduce(function(a,e){return a+e[1];},0)||1;
    return'<div style="margin-bottom:12px"><div style="font-size:10px;color:var(--mu);letter-spacing:1px;margin-bottom:6px">'+sec.t+'</div>'
      +entries.map(function(e){var pct=Math.round(e[1]/tot*100);return'<div class="dev-bar"><span class="dev-bar-label">'+_esc(e[0])+'</span><div style="flex:1;height:5px;background:rgba(255,255,255,.04);border-radius:3px;overflow:hidden"><div class="dev-bar-fill" style="width:'+pct+'%"></div></div><span class="dev-bar-val">'+e[1]+'</span></div>';}).join("")+'</div>';
  }).join("");
}

// ── Visitors ──
function _loadVisitors(){
  _api("/api/analytics").then(function(d){
    var el=document.getElementById("visitors-list");if(!el)return;
    var vis=d.visitors||[];
    if(!vis.length){el.innerHTML='<div style="color:var(--mu);font-size:11px;text-align:center;padding:20px">لا توجد بيانات</div>';return;}
    el.innerHTML='<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:10px">'
      +'<thead><tr>'+["الجهاز","OS","المتصفح","الفئة","المصدر","زيارات"].map(function(h){return'<th style="padding:6px;text-align:right;color:var(--mu);border-bottom:1px solid rgba(255,255,255,.06)">'+h+'</th>';}).join("")+'</tr></thead>'
      +'<tbody>'+vis.slice(0,80).map(function(v){var tc=v.tier==="flagship"?"rgba(192,132,252,.7)":v.tier==="mid"?"rgba(74,222,128,.6)":"rgba(251,191,36,.6)";return'<tr><td style="padding:5px 6px;color:var(--dim)">'+_esc(v.dev||"")+'</td><td style="padding:5px 6px;color:var(--dim)">'+_esc(v.os||"")+'</td><td style="padding:5px 6px;color:var(--dim)">'+_esc(v.browser||"")+'</td><td style="padding:5px 6px;color:'+tc+'">'+_esc(v.tier||"")+'</td><td style="padding:5px 6px;color:var(--dim)">'+_esc(v.source||"")+'</td><td style="padding:5px 6px;color:var(--mu)">'+v.count+'</td></tr>';}).join("")+'</tbody></table></div>';
  }).catch(function(){});
}
function _clearVisitors(){_api("/api/analytics?range=all",{method:"DELETE"}).then(function(){_loadVisitors();_toast("تم المسح");}).catch(function(){_toast("خطأ");});}

// ── م25: Stock History ──
function _loadStockHistory(){
  _api("/api/stock-history").then(function(hist){
    var el=document.getElementById("stock-hist-list");if(!el)return;
    if(!hist.length){el.innerHTML='<div style="color:var(--mu);font-size:11px;text-align:center;padding:20px">لا توجد سجلات</div>';return;}
    el.innerHTML=hist.map(function(h){return'<div class="stock-row">'
      +'<span style="font-weight:700;color:'+(h.qty>0?"rgba(74,222,128,.8)":"rgba(252,165,165,.8)")+'">'+(h.qty>0?"+":"")+h.qty+'</span>'
      +'<div><div style="font-size:11px;color:var(--tx)">'+_esc(h.productName||"")+'</div><div style="font-size:10px;color:var(--mu)">'+_esc(h.reason||h.type||"")+'</div></div>'
      +'<span style="font-size:10px;color:var(--mu)">رصيد: '+h.balanceAfter+'</span>'
      +'<span style="font-size:9px;color:rgba(168,85,247,.4)">'+new Date(h.t||"").toLocaleDateString("ar-DZ")+'</span>'
      +'</div>';}).join("");
  }).catch(function(){});
  _api("/api/products").then(function(prods){
    var sel=document.getElementById("stock-prod-sel");if(!sel)return;
    sel.innerHTML=prods.map(function(p){return'<option value="'+p.id+'">'+_esc(p.name||"")+" ("+(p.quantity!==null&&p.quantity!==undefined?p.quantity:"∞")+')</option>';}).join("");
  }).catch(function(){});
}
function _addStock(){
  var G=function(i){return((document.getElementById(i)||{}).value||"");};
  var pid=G("stock-prod-sel"),qty=parseInt(G("stock-qty")),reason=G("stock-reason").trim()||"تعديل يدوي";
  if(!pid||!qty){_toast("ادخل المنتج والكمية");return;}
  _api("/api/stock-history",{method:"POST",body:JSON.stringify({productId:pid,qty:qty,reason:reason})})
  .then(function(d){_loadStockHistory();_toast("رصيد جديد: "+d.newQty);}).catch(function(){_toast("خطأ");});
}

// ── Reviews Admin ──
function _loadReviews(){_showRvTab("reviews",null);}
function _showRvTab(tab,el2){
  document.querySelectorAll("#sec-reviews .aibtn").forEach(function(b){b.classList.remove("on");});
  if(el2)el2.classList.add("on");
  var inn=document.getElementById("sec-reviews-inner");if(!inn)return;
  if(tab==="reviews"){
    _api("/api/reviews").then(function(revs){
      if(!revs.length){inn.innerHTML='<div style="color:var(--mu);font-size:11px;text-align:center;padding:20px">لا توجد تقييمات</div>';return;}
      inn.innerHTML=revs.map(function(r){return'<div class="rv-card '+(r.approved?"":"rv-pending")+'">'
        +'<div class="rv-card-stars">'+"&#9733;".repeat(r.rating||5)+'</div>'
        +'<div class="rv-card-body">'+_esc(r.body||"")+'</div>'
        +'<div class="rv-card-name">'+_esc(r.name||"")+(r.phone?" — "+_esc(r.phone):"")+'</div>'
        +'<div style="display:flex;gap:6px;margin-top:8px">'
        +'<button class="aibtn" onclick="WOW._approveReview('+r.id+','+(!r.approved)+')">'+(r.approved?"ايقاف":"موافقة")+'</button>'
        +'<button class="aibtn" onclick="WOW._promoteTestimonial('+r.id+')">ترقية لشهادة</button>'
        +'<button class="aibtn del" onclick="WOW._deleteReview('+r.id+')">&#10005;</button>'
        +'</div></div>';}).join("");
    }).catch(function(){});
  } else if(tab==="testimonials"){
    _api("/api/testimonials").then(function(tl){
      if(!tl.length){inn.innerHTML='<div style="color:var(--mu);font-size:11px;text-align:center;padding:20px">لا توجد شهادات</div>';return;}
      inn.innerHTML=tl.map(function(t){return'<div class="rv-card"><div class="rv-card-stars">'+"&#9733;".repeat(t.rating||5)+'</div><div class="rv-card-body">'+_esc(t.body||"")+'</div><div class="rv-card-name">'+_esc(t.name||"")+'</div><button class="aibtn del" style="margin-top:8px" onclick="WOW._deleteTestimonial('+t.id+')">&#10005;</button></div>';}).join("");
    }).catch(function(){});
  } else if(tab==="add"){
    inn.innerHTML='<div class="af"><label>الاسم</label><input class="ainp" id="nt-name" placeholder="اسم العميل"></div>'
      +'<div class="af"><label>الشهادة</label><textarea class="ainp" id="nt-body" rows="3" style="resize:vertical;min-height:70px" placeholder="رأي العميل..."></textarea></div>'
      +'<div class="af"><label>التقييم (1-5)</label><input class="ainp" id="nt-rating" type="number" min="1" max="5" value="5" inputmode="numeric"></div>'
      +'<button class="btn-main" onclick="WOW._addTestimonial()">اضافة الشهادة</button>';
  }
}
function _approveReview(id,val){_api("/api/reviews",{method:"PATCH",body:JSON.stringify({id:id,approved:val})}).then(function(){_showRvTab("reviews",null);}).catch(function(){_toast("خطأ");});}
function _deleteReview(id){_api("/api/reviews?id="+id,{method:"DELETE"}).then(function(){_showRvTab("reviews",null);_toast("تم الحذف");}).catch(function(){_toast("خطأ");});}
function _promoteTestimonial(rid){
  _api("/api/reviews").then(function(revs){
    var r=revs.find(function(x){return x.id===rid||x.id===+rid;});if(!r)return;
    return _api("/api/testimonials",{method:"POST",body:JSON.stringify({name:r.name,body:r.body,rating:r.rating})});
  }).then(function(){_toast("تمت الترقية لشهادة");}).catch(function(){_toast("خطأ");});
}
function _addTestimonial(){
  var G=function(i){return((document.getElementById(i)||{}).value||"");};
  _api("/api/testimonials",{method:"POST",body:JSON.stringify({name:G("nt-name").trim(),body:G("nt-body").trim(),rating:parseInt(G("nt-rating"))||5})})
  .then(function(){_showRvTab("testimonials",null);_toast("تمت الاضافة");}).catch(function(){_toast("خطأ");});
}
function _deleteTestimonial(id){_api("/api/testimonials?id="+id,{method:"DELETE"}).then(function(){_showRvTab("testimonials",null);_toast("تم الحذف");}).catch(function(){_toast("خطأ");});}

// ── Loyalty ──
function _loadLoyalty(phone){
  var el=document.getElementById("loyalty-list");if(!el)return;
  var url=phone&&phone.trim()?"/api/loyalty?phone="+encodeURIComponent(phone.trim()):"/api/loyalty";
  _api(url).then(function(d){
    if(Array.isArray(d)){
      if(!d.length){el.innerHTML='<div style="color:var(--mu);font-size:11px;text-align:center;padding:20px">لا توجد بيانات</div>';return;}
      el.innerHTML=d.map(function(u){return'<div style="display:flex;justify-content:space-between;align-items:center;padding:9px 12px;border:1px solid rgba(255,255,255,.06);border-radius:9px;margin-bottom:6px;font-size:11px"><div><div style="color:var(--tx)">'+_esc(u.name||u.phone||"")+'</div><div style="color:var(--mu)">'+_esc(u.phone||"")+'</div></div><button class="aibtn" onclick="WOW._loadLoyalty(\''+_esc(u.phone)+'\')">عرض</button></div>';}).join("");
    } else {
      el.innerHTML='<div style="background:rgba(251,191,36,.07);border:1px solid rgba(251,191,36,.15);border-radius:12px;padding:14px">'
        +'<div style="font-family:Georgia,serif;font-size:20px;color:rgba(251,191,36,.9);margin-bottom:4px">'+(d.points||0)+' نقطة</div>'
        +'<div style="font-size:11px;color:var(--mu);margin-bottom:12px">آخر المعاملات</div>'
        +(d.history||[]).slice(0,8).map(function(h){return'<div style="display:flex;justify-content:space-between;font-size:10px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.05)"><span style="color:var(--mu)">'+new Date(h.t||"").toLocaleDateString("ar-DZ")+'</span><span style="color:rgba(251,191,36,.8)">+'+h.earned+' نقطة</span></div>';}).join("")
        +'</div>';
    }
  }).catch(function(){el.innerHTML='<div style="color:var(--mu);font-size:11px;text-align:center;padding:20px">خطأ في التحميل</div>';});
}

// ── م35: Activity Log ──
function _loadActivity(){
  var type=(document.getElementById("act-type-flt")||{}).value||"";
  var actor=(document.getElementById("act-actor-flt")||{}).value||"";
  var url="/api/activity-log"+(type||actor?"?"+(type?"type="+encodeURIComponent(type):"")+(type&&actor?"&":"")+(actor?"actor="+encodeURIComponent(actor):""):"");
  _api(url).then(function(log){
    var el=document.getElementById("activity-list");if(!el)return;
    if(!log.length){el.innerHTML='<div style="color:var(--mu);font-size:11px;text-align:center;padding:20px">السجل فارغ</div>';return;}
    el.innerHTML=log.slice(0,200).map(function(e){return'<div class="audit-row">'
      +'<span class="audit-ts">'+(e.t||"").substring(0,16)+'</span>'
      +'<span class="audit-type">'+_esc(e.type||"")+'</span>'
      +'<span style="color:rgba(192,132,252,.6)">'+_esc(e.actor||"system")+'</span>'
      +'<span style="flex:1;color:var(--mu)">'+_esc(e.details||"")+'</span>'
      +'</div>';}).join("");
  }).catch(function(){});
}

// ── Settings ──
function _saveSettings(){
  var G=function(i){return((document.getElementById(i)||{}).value||"");};
  var C=function(i){var el=document.getElementById(i);return el?el.checked:true;};
  var featbar=G("s-featbar").split("\n").map(function(l){return l.trim();}).filter(Boolean);
  _api("/api/settings",{method:"POST",body:JSON.stringify({
    storeName:G("s-name").trim(),whatsapp:G("s-wa").trim(),email:G("s-em").trim(),
    instagram:G("s-ig").trim(),admin_discount:parseInt(G("s-disc"))||0,
    hero_background:G("s-bg").trim(),about:G("s-about").trim(),
    faq:G("s-faq").trim(),refundPolicy:G("s-refund").trim(),
    featuresBar:featbar,showFeatureBar:C("s-show-featbar"),
    showFaq:C("s-show-faq"),showRefundPolicy:C("s-show-refund"),showTrustBadges:C("s-show-badges"),
    lang:G("s-lang")||"ar"
  })}).then(function(){_toast("تم حفظ الاعدادات");}).catch(function(){_toast("خطأ في الحفظ");});
}

// ── Push Notifications ──
function _initPush(){
  if(!("serviceWorker"in navigator)||!("PushManager"in window))return;
  navigator.serviceWorker.register("/sw.js").then(function(reg){
    var btn=document.getElementById("push-btn");if(!btn)return;
    btn.addEventListener("click",function(){
      Notification.requestPermission().then(function(perm){
        if(perm!=="granted"){_toast("لم يتم منح الاذن");return;}
        reg.pushManager.subscribe({userVisibleOnly:true}).then(function(sub){
          _api("/api/push-subscribe",{method:"POST",body:JSON.stringify(sub)}).then(function(){_toast("تم تفعيل الاشعارات");}).catch(function(){});
        }).catch(function(){_toast("تفعيل الاشعارات من المتصفح مباشرة");});
      });
    });
  }).catch(function(){});
}

// ── Init ──
var _initDone=false;
function _init(){
  if(_initDone)return;_initDone=true;
  _trackVisit();
  _initScrollProg();
  _initKeyboard();
  _initConfirmDel();
  _renderTrustBadges();
  _initPush();
  // Hero BG
  var bg="${_esc(s.hero_background||"")}";
  if(bg)_initHero(bg);
  // Qty controls
  var qd=document.getElementById("qty-dec"),qi2=document.getElementById("qty-inc"),qI=document.getElementById("mod-qty");
  if(qd&&qi2&&qI){
    qd.addEventListener("click",function(){qI.value=Math.max(1,parseInt(qI.value||1)-1);});
    qi2.addEventListener("click",function(){qI.value=Math.min(99,parseInt(qI.value||1)+1);});
  }
  // Search
  var si=document.getElementById("search-inp");
  if(si){
    si.addEventListener("input",function(){_liveSearch(this.value);});
    si.addEventListener("search",function(){_liveSearch(this.value);});
  }
  // Admin btn
  var admB=document.getElementById("adm-btn");if(admB)admB.addEventListener("click",_openAdm);
  // Cart btn
  var cartB=document.getElementById("cart-btn");if(cartB)cartB.addEventListener("click",openCart);
  // Admin close
  var admCl=document.getElementById("adm-close-btn");if(admCl)admCl.addEventListener("click",closeAdm);
  // Admin login enter key
  var ap=document.getElementById("adm-pass");
  if(ap)ap.addEventListener("keydown",function(e){if(e.key==="Enter")_doLogin();});
  // Track order enter
  var ti=document.getElementById("track-inp");
  if(ti)ti.addEventListener("keydown",function(e){if(e.key==="Enter")doTrack();});
  // Drop zone
  var dz=document.getElementById("drop-zone"),pf=document.getElementById("p-img-file");
  if(dz){
    dz.addEventListener("click",function(){if(pf)pf.click();});
    dz.addEventListener("keydown",function(e){if(e.key===" "||e.key==="Enter"){e.preventDefault();if(pf)pf.click();}});
    dz.addEventListener("dragover",function(e){e.preventDefault();dz.classList.add("drag");});
    dz.addEventListener("dragleave",function(){dz.classList.remove("drag");});
    dz.addEventListener("drop",_handleDrop);
  }
  if(pf)pf.addEventListener("change",function(){_handleImgs(this.files);this.value="";});
  // Save btn
  var sb2=document.getElementById("save-btn");if(sb2)sb2.addEventListener("click",_saveProd);
  // Cancel edit
  var cb2=document.getElementById("cancel-edit-btn");if(cb2)cb2.addEventListener("click",_cancelEdit);
  // Save settings
  var ssb=document.getElementById("save-settings-btn");if(ssb)ssb.addEventListener("click",_saveSettings);
  // Orders refresh
  var orb=document.getElementById("orders-refresh-btn");if(orb)orb.addEventListener("click",_loadOrders);
  // Orders clear
  var ocb=document.getElementById("orders-clear-btn");if(ocb)ocb.addEventListener("click",_clearOrders);
  // Goto addprod
  var gap=document.getElementById("goto-addprod");if(gap)gap.addEventListener("click",function(){_aTab("addprod",null);});
  // Admin login btn
  var alb=document.getElementById("adm-login-btn");if(alb)alb.addEventListener("click",_doLogin);
  // Fullscreen btn
  var fsb=document.getElementById("fullscreen-btn");if(fsb)fsb.addEventListener("click",_toggleFullscreen);
  // URL params restore filters
  try{
    var sp=new URLSearchParams(location.search);
    if(sp.get("s"))document.getElementById("ord-search").value=sp.get("s");
    if(sp.get("st"))document.getElementById("ord-flt-status").value=sp.get("st");
    if(sp.get("w"))document.getElementById("ord-flt-wilaya").value=sp.get("w");
    if(sp.get("c"))document.getElementById("ord-flt-confirmed").value=sp.get("c");
  }catch(e){}
  // Auto-open product from URL ?openProd=id
  try{
    var sp2=new URLSearchParams(location.search);var pid2=sp2.get("openProd");
    if(pid2)setTimeout(function(){var p=_prods.find(function(x){return String(x.id)===String(pid2);});if(p)_openProd(pid2);},800);
  }catch(e){}
  // Referral code
  try{var sp3=new URLSearchParams(location.search);var ref=sp3.get("ref");if(ref)localStorage.setItem("wow_ref",ref);}catch(e){}
  // Load products
  _loadProds();
}

// ── Public API ──
return {
  flt:_flt,openProd:_openProd,closeMod:_closeMod,openSizeMod:openSizeMod,
  pmImg:pmImg,pickSz:pickSz,pickClr:pickClr,pickVariant:pickVariant,
  sTo:_sTo,sPrev:_sPrev,sNext:_sNext,
  openCart:openCart,closeCart:closeCart,
  openCheckout:openCheckout,closeChk:closeChk,
  chkNext:chkNext,chkPrev:chkPrev,updPreview:updPreview,
  confirmAdd:confirmAdd,submitOrder:submitOrder,doTrack:doTrack,
  doLogin:_doLogin,closeAdm:closeAdm,
  aTab:_aTab,
  editProd:_editProd,delProd:_delProd,
  delImg:_delImg,calcDisc:_calcDisc,
  _showQR:_showQR,_copyProdLink:_copyProdLink,
  _openFaq:_openFaq,_openRefund:_openRefund,
  _applyCoupon:_applyCoupon,
  _filterOrders:_filterOrders,_toggleOrder:_toggleOrder,
  _confOrd:_confOrd,_updStatus:_updStatus,_delOrder:_delOrder,
  _debouncedNote:_debouncedNote,
  _toggleBulk:_toggleBulk,_clearBulk:_clearBulk,
  _bulkPrint:_bulkPrint,_bulkConfirm:_bulkConfirm,_bulkStatus:_bulkStatus,
  _groupOrders:_groupOrders,_exportCSV:_exportCSV,_doExportCSV:_doExportCSV,
  _filterAdminProds:_filterAdminProds,
  _archiveProd:_archiveProd,
  _loadArchive:_loadArchive,_toggleArchSel:_toggleArchSel,
  _archSelectAll:_archSelectAll,_restoreProd:_restoreProd,_bulkRestore:_bulkRestore,
  _createCoupon:_createCoupon,_toggleCoupon:_toggleCoupon,_deleteCoupon:_deleteCoupon,
  _addStock:_addStock,
  _showRvTab:_showRvTab,_approveReview:_approveReview,
  _deleteReview:_deleteReview,_promoteTestimonial:_promoteTestimonial,
  _addTestimonial:_addTestimonial,
  _submitReview:_submitReview,_openReviewMod:_openReviewMod,_setRating:_setRating,
  _joinWaitlist:_joinWaitlist,
  _loadLoyalty:_loadLoyalty,
  _loadActivity:_loadActivity,
  _clearVisitors:_clearVisitors,
  _toggleFullscreen:_toggleFullscreen,
  _switchLang:_switchLang,
  _addBundle:_addBundle,
  _removeCart:_removeCart,
  _deleteTestimonial:_deleteTestimonial,
  _init:_init,
};
})();

document.addEventListener("DOMContentLoaded",function(){if(typeof WOW!=="undefined"&&WOW._init)WOW._init();});
(function(){var r=new MutationObserver(function(m,obs){var el=document.getElementById("prod-grid");if(el&&typeof WOW!=="undefined"){WOW._init&&WOW._init();obs.disconnect();}});r.observe(document.body,{childList:true,subtree:false});})();
window.addEventListener("load",function(){if(typeof WOW!=="undefined"&&WOW._init)WOW._init();});
</script>
</body>
</html>\`;
}
