// ═══════════════════════════════════════════════════════════════
// WOW STORE — Cloudflare Worker — v11.0 — wow-store1.bdalwhabbwznad8.workers.dev
// KV Binding : env.DATABASE
// ═══════════════════════════════════════════════════════════════

async function hashPass(str){
  const buf=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}

// Admin password hash only; keep the raw password out of source control.
const ADMIN_PASS_HASH = "881b9563ffff9349eb3ad4efeb71c7355d7878644e385d71d26b846f3ddd06a6";
const BLOCK_MS = 8*3600000;
const MAX_ATT  = 5;

// ── قائمة النطاقات المسموح بها لـ CORS — عدّلها يدوياً حسب نطاقك ──
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
  var BARS=[
    "11011001100","11001101100","11001100110","10010011000","10010001100","10001001100","10011001000",
    "10011000100","10001100100","11001001000","11001000100","11000100100","10110011100","10011011100",
    "10011001110","10111001100","10011101100","10011100110","11001110010","11001011100","11001001110",
    "11011100100","11001110100","11101101110","11101001100","11100101100","11100100110","11101100100",
    "11100110100","11100110010","11011011000","11011000110","11000110110","10100011000","10001011000",
    "10001000110","10110001000","10001101000","10001100010","11010001000","11000101000","11000100010",
    "10110111000","10110001110","10001101110","10111011000","10111000110","10001110110","11101110110",
    "11010001110","11000101110","11011101000","11011100010","11101011000","11101000110","11100010110",
    "11101101000","11101100010","11100011010","11101111010","11001000010","11110001010","10100110000",
    "10100001100","10010110000","10010000110","10000101100","10000100110","10110010000","10110000100",
    "10011010000","10011000010","10000110100","10000110010","11000010010","11001010000","11110111010",
    "11000010100","10001111010","10100111100","10010111100","11110100010","11110010010","11011111010",
    "11111011010","11001111010","10100011110","10001011110","10010001111","10000101111","11011110100",
    "11011110010","11110100100","11110010100","11110101000","11110101100","11100111010","11110111100",
    "11010111100","11110101110","11011010000","11011010110",
    "11010000100","11010010000","11010011100","11000111010"
  ];
  var BVALS={" ":0,"!":1,'"':2,"#":3,"$":4,"%":5,"&":6,"'":7,"(":8,")":9,
    "*":10,"+":11,",":12,"-":13,".":14,"/":15,
    "0":16,"1":17,"2":18,"3":19,"4":20,"5":21,"6":22,"7":23,"8":24,"9":25,
    ":":26,";":27,"<":28,"=":29,">":30,"?":31,"@":32,
    "A":33,"B":34,"C":35,"D":36,"E":37,"F":38,"G":39,"H":40,"I":41,"J":42,
    "K":43,"L":44,"M":45,"N":46,"O":47,"P":48,"Q":49,"R":50,"S":51,"T":52,
    "U":53,"V":54,"W":55,"X":56,"Y":57,"Z":58,
    "[":59,"\\":60,"]":61,"^":62,"_":63,"`":64,
    "a":65,"b":66,"c":67,"d":68,"e":69,"f":70,"g":71,"h":72,"i":73,"j":74,
    "k":75,"l":76,"m":77,"n":78,"o":79,"p":80,"q":81,"r":82,"s":83,"t":84,
    "u":85,"v":86,"w":87,"x":88,"y":89,"z":90,"{":91,"|":92,"}":93,"~":94};
  var safe=text.replace(/[^ -~]/g,"").substring(0,24)||"?";
  var START_B=104,STOP=106;
  var dataVals=[];
  for(var i=0;i<safe.length;i++){var v=BVALS[safe[i]];if(v!==undefined)dataVals.push(v);}
  var chk=START_B;
  for(var dataIdx=0;dataIdx<dataVals.length;dataIdx++)chk=(chk+dataVals[dataIdx]*(dataIdx+1))%103;
  var allVals=[START_B].concat(dataVals).concat([chk,STOP]);
  var bits="";
  allVals.forEach(function(v){bits+=BARS[v]||"";});
  bits+="11";
  var M=2,PAD=10,H=64;
  var W=bits.length*M+PAD*2;
  var svg='<svg xmlns="http://www.w3.org/2000/svg" width="'+W+'" height="'+H+'" viewBox="0 0 '+W+' '+H+'">'
    +'<rect width="'+W+'" height="'+H+'" fill="#fff"/>';
  var x=PAD;
  for(var bitIdx=0;bitIdx<bits.length;bitIdx++){
    if(bits[bitIdx]==="1")svg+='<rect x="'+x+'" y="4" width="'+M+'" height="'+(H-16)+'" fill="#111"/>';
    x+=M;
  }
  svg+='<text x="'+(W/2)+'" y="'+(H-3)+'" text-anchor="middle" font-size="8" font-family="monospace" fill="#333">'+safe+'</text></svg>';
  return svg;
}

function buildInvoiceHTML(o,s,opts){
  /* opts = {hideShipping,extraNote,scale,printTracked} — passed from query params */
  opts=opts||{};
  const sn=_escSrv(s.storeName||"WOW STORE"),wa=_escSrv(s.whatsapp||"");
  const ST={processing:"\u0642\u064a\u062f \u0627\u0644\u0645\u0639\u0627\u0644\u062c\u0629",shipped:"\u062a\u0645 \u0627\u0644\u0634\u062d\u0646",delivered:"\u062a\u0645 \u0627\u0644\u062a\u0648\u0635\u064a\u0644",returned:"\u0645\u064f\u0631\u062a\u062c\u0639\u0629"};
  const SC={processing:"#f59e0b",shipped:"#3b82f6",delivered:"#22c55e",returned:"#ef4444"};
  const stTxt=ST[o.status]||o.status||"";const stC=SC[o.status]||"#a855f7";
  const hideShip=opts.hideShipping||false;
  const extraNote=opts.extraNote||"";
  const scale=Math.min(2,Math.max(0.5,parseFloat(opts.scale)||1));
  const iH=(o.items||[]).map(it=>`<tr><td style="padding:6px;border-bottom:1px solid #eee">${it.img?`<img src="${_escSrv(it.img)}" style="width:42px;height:52px;object-fit:cover;border-radius:4px">`:""}</td><td style="padding:6px;border-bottom:1px solid #eee;font-size:${Math.round(12*scale)}px">${_escSrv(it.name||"")}${it.size?` <small style="color:#888">[${_escSrv(it.size)}]</small>`:""}</td><td style="padding:6px;border-bottom:1px solid #eee;text-align:center;font-size:${Math.round(12*scale)}px">${it.qty||1}</td><td style="padding:6px;border-bottom:1px solid #eee;font-size:${Math.round(12*scale)}px;white-space:nowrap">${((it.price||0)*(it.qty||1)).toLocaleString()} \u062f\u062c</td></tr>`).join("");
  const printedAt=opts.printTracked?`<div style="font-size:9px;color:#bbb;text-align:center;padding:4px 0;border-top:1px solid #eee;margin-top:4px">\u0637\u0628\u0627\u0639\u0629 \u0628\u062a\u0627\u0631\u064a\u062e: ${new Date().toLocaleString("ar-DZ")}</div>`:"";
  const baseFz=Math.round(14*scale);
  return `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>\u0641\u0627\u062a\u0648\u0631\u0629 \u2014 ${o.id}</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f5f5;padding:16px;color:#111;font-size:${baseFz}px}.wrap{max-width:580px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.1)}.hdr{background:#0a0016;color:#fff;padding:22px;text-align:center}.brand{font-family:Georgia,serif;font-size:${Math.round(34*scale)}px;font-weight:900;letter-spacing:6px;color:#c084fc}.sub{font-size:10px;color:rgba(255,255,255,.4);letter-spacing:3px;margin-top:2px}.oid{font-size:12px;color:rgba(255,255,255,.5);margin-top:10px}.dt{font-size:11px;color:rgba(255,255,255,.3)}.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;margin-top:8px;background:${stC}22;color:${stC}}.body{padding:18px}.row{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px}.col{flex:1;min-width:160px;background:#fafafa;border-radius:8px;padding:12px}.col h4{font-size:9px;color:#888;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;border-bottom:1px solid #eee;padding-bottom:4px}.col p{font-size:${Math.round(11*scale)}px;color:#444;line-height:1.9}table{width:100%;border-collapse:collapse;margin-bottom:14px}thead th{padding:7px 6px;font-size:9px;color:#888;letter-spacing:1px;text-transform:uppercase;text-align:right;background:#fafafa}thead th:last-child{text-align:left}.totbox{background:#fafafa;border-radius:8px;padding:12px 14px}.tr{display:flex;justify-content:space-between;font-size:${Math.round(12*scale)}px;color:#555;padding:2px 0}.tr.final{font-size:${Math.round(15*scale)}px;font-weight:700;color:#111;border-top:2px solid #e0e0e0;margin-top:6px;padding-top:8px}.no-print{text-align:center;margin-bottom:14px;display:flex;gap:6px;justify-content:center;flex-wrap:wrap}.no-print button,.no-print select,.no-print input{font-size:11px;border-radius:7px;padding:7px 12px;border:1px solid #ddd;cursor:pointer}.no-print label{font-size:11px;display:flex;align-items:center;gap:4px}.pdf-hint{background:#f0f9ff;border:1px solid #bae6fd;border-radius:6px;padding:8px 12px;font-size:10px;color:#0369a1;text-align:center;margin-bottom:10px}.ft{text-align:center;padding:14px;color:#aaa;font-size:10px;border-top:1px solid #eee}@media print{.no-print{display:none}.pdf-hint{display:none}body{background:#fff;padding:0}.wrap{box-shadow:none;border-radius:0}}</style></head>
<body>
<div class="no-print">
  <button onclick="window.print()" style="background:#6d28d9;color:#fff;border-color:#6d28d9">\u0637\u0628\u0627\u0639\u0629</button>
  <button onclick="window.close()" style="background:#eee;color:#333">\u0625\u063a\u0644\u0627\u0642</button>
  <label><input type="checkbox" id="hideShipChk" ${hideShip?"checked":""}> \u0625\u062e\u0641\u0627\u0621 \u0627\u0644\u0634\u062d\u0646</label>
  <select id="scaleSelect" onchange="document.body.style.fontSize=parseFloat(this.value)*14+'px'">
    <option value="0.8" ${scale<0.9?"selected":""}>80%</option>
    <option value="1" ${scale>=0.9&&scale<1.15?"selected":""}>100%</option>
    <option value="1.2" ${scale>=1.15?"selected":""}>120%</option>
  </select>
  <input id="noteInp" type="text" placeholder="\u0645\u0644\u0627\u062d\u0638\u0629 \u0645\u062e\u0635\u0635\u0629..." value="${_escSrv(extraNote)}" style="min-width:160px">
  <button onclick="(function(){var n=document.getElementById('noteInp').value;var h=document.getElementById('hideShipChk').checked;var sc=document.getElementById('scaleSelect').value;window.location.href='/invoice?id=${o.id}&hideShip='+h+'&note='+encodeURIComponent(n)+'&scale='+sc+'&pt=1';})()" style="background:#059669;color:#fff;border-color:#059669">\u062a\u0637\u0628\u064a\u0642</button>
</div>
<div class="pdf-hint">\u0644\u062d\u0641\u0638 PDF: \u0641\u064a \u0646\u0627\u0641\u0630\u0629 \u0627\u0644\u0637\u0628\u0627\u0639\u0629 \u0627\u062e\u062a\u0631 &ldquo;Save as PDF&rdquo; \u0643\u0627\u0644\u0637\u0627\u0628\u0639\u0629</div>
<div class="wrap">
<div class="hdr"><div class="brand">${sn}</div><div class="sub">INVOICE &middot; \u0641\u0627\u062a\u0648\u0631\u0629</div><div class="oid">${_escSrv(o.id)}</div><div class="dt">${new Date(o.date).toLocaleString("ar-DZ")}</div><div class="badge">${stTxt}</div></div>
<div class="body">
<div class="row">
<div class="col"><h4>\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0639\u0645\u064a\u0644</h4><p><strong>${_escSrv(o.name||"")}</strong></p><p>${_escSrv(o.phone1||"")} / ${_escSrv(o.phone2||"")}</p>${o.email?`<p>${_escSrv(o.email)}</p>`:""}</div>
<div class="col"><h4>\u0627\u0644\u062a\u0648\u0635\u064a\u0644</h4><p>${_escSrv(o.wilaya||"")} / ${_escSrv(o.commune||"")}</p><p>${_escSrv(o.dlbl||"Stop Desk")}</p><p>${o.payMethod==="ccp"?"CCP \u0645\u0633\u0628\u0642":"\u0627\u0644\u062f\u0641\u0639 \u0639\u0646\u062f \u0627\u0644\u0627\u0633\u062a\u0644\u0627\u0645"}</p>${o.confirmed?`<p style="color:#22c55e">\u0645\u0624\u0643\u062f\u0629</p>`:`<p style="color:#f59e0b">\u0628\u0627\u0646\u062a\u0638\u0627\u0631</p>`}</div>
</div>
<table><thead><tr><th>\u0635\u0648\u0631\u0629</th><th>\u0627\u0644\u0645\u0646\u062a\u062c</th><th style="text-align:center">\u0627\u0644\u0643\u0645\u064a\u0629</th><th style="text-align:left">\u0627\u0644\u0645\u0628\u0644\u063a</th></tr></thead><tbody>${iH}</tbody></table>
<div class="totbox" id="totbox">
<div class="tr"><span>\u0627\u0644\u0645\u0646\u062a\u062c\u0627\u062a</span><span>${(o.originalSub||o.finalSub||0).toLocaleString()} \u062f\u062c</span></div>
${o.discAmt>0?`<div class="tr" style="color:#22c55e"><span>\u062e\u0635\u0645 \u0627\u0644\u0639\u0631\u0636</span><span>- ${o.discAmt.toLocaleString()} \u062f\u062c</span></div>`:""}
${o.couponCode?`<div class="tr" style="color:#22c55e"><span>\u0643\u0648\u0628\u0648\u0646 (${_escSrv(o.couponCode)})</span><span>- ${(o.couponDisc||0).toLocaleString()} \u062f\u062c</span></div>`:""}
<div class="tr" id="ship-row"><span>\u0631\u0633\u0648\u0645 \u0627\u0644\u062a\u0648\u0635\u064a\u0644</span><span>${(o.fee||0).toLocaleString()} \u062f\u062c</span></div>
${o.ccpDisc>0?`<div class="tr" style="color:#22c55e"><span>\u062e\u0635\u0645 CCP</span><span>- ${o.ccpDisc} \u062f\u062c</span></div>`:""}
<div class="tr final"><span>\u0627\u0644\u0645\u062c\u0645\u0648\u0639 \u0627\u0644\u0643\u0644\u064a</span><span>${(o.total||0).toLocaleString()} \u062f\u062c</span></div>
</div>
${o.note||extraNote?`<div style="margin-top:12px;background:#fff9e6;border:1px solid #fcd34d;border-radius:6px;padding:9px 11px;font-size:${Math.round(11*scale)}px;color:#92400e"><strong>\u0645\u0644\u0627\u062d\u0638\u0629:</strong> ${_escSrv(o.note||"")}${extraNote?` — ${_escSrv(extraNote)}`:""}</div>`:""}
${opts.printTracked?printedAt:""}
</div>
<div class="ft">${sn} &middot; ${wa}</div>
</div>
<script>
(function(){
  var hc=document.getElementById("hideShipChk");
  function applyHide(){
    var sr=document.getElementById("ship-row");
    if(sr)sr.style.display=hc&&hc.checked?"none":"flex";
  }
  if(hc){hc.addEventListener("change",applyHide);applyHide();}
})();
</script>
</body></html>`;
}

function buildShippingLabel(o,s,fmt){
  const sn=_escSrv(s.storeName||"WOW STORE"),wa=_escSrv(s.whatsapp||"");
  const FMT_LABELS={yalidine:"Yalidine Express",zr:"Zr Express",maystro:"Maystro Delivery"};
  const fmtLabel=FMT_LABELS[fmt]||"Yalidine Express";
  const iL=(o.items||[]).map(it=>`${it.name||""}${it.size?" ["+it.size+"]":""} x${it.qty||1}`).join("\u060c ");
  const bc=encodeCode128((o.id||"WOW").substring(0,20));
  const isPrepaid=o.payMethod==="ccp";
  const codAmt=isPrepaid?0:(o.total||0);
  const printDate=new Date(o.date).toLocaleDateString("ar-DZ");
  /* Format-specific accent color */
  const fmtColor={yalidine:"#e63946",zr:"#2196f3",maystro:"#ff6f00"}[fmt]||"#e63946";
  return `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<title>\u0628\u0648\u0644\u064a\u0635\u0629 \u2014 ${_escSrv(o.id)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f5f5;padding:16px;color:#111}
.label{width:148mm;min-height:105mm;background:#fff;border:2px solid #111;border-radius:6px;padding:12px;position:relative}
.hdr{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2.5px solid #111;padding-bottom:9px;margin-bottom:9px}
.brand{font-family:Georgia,serif;font-size:22px;font-weight:900;letter-spacing:5px;color:#111}
.brand-wa{font-size:9px;color:#555;margin-top:3px}
.fmt-badge{background:${fmtColor};color:#fff;font-size:8px;font-weight:700;padding:3px 9px;border-radius:3px;letter-spacing:1px;text-transform:uppercase}
.order-id{font-size:12px;font-weight:700;margin-top:4px;direction:ltr;letter-spacing:.5px}
.order-date{font-size:9px;color:#777;margin-top:2px}
.bc-wrap{text-align:center;margin:6px 0;overflow:hidden;max-width:100%}
.addresses{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px}
.addr-box{border:1px solid #ddd;border-radius:4px;padding:8px}
.addr-box.recv{border-color:#111;border-width:1.5px}
.addr-lbl{font-size:7px;color:#888;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;padding-bottom:3px;border-bottom:1px solid #eee}
.addr-name{font-size:12px;font-weight:700;margin-bottom:2px}
.addr-detail{font-size:10px;color:#444;line-height:1.7}
.items-row{background:#f9f9f9;border:1px solid #eee;border-radius:4px;padding:7px 9px;font-size:10px;color:#555;margin-bottom:8px;line-height:1.6}
.items-lbl{font-size:7px;color:#888;letter-spacing:2px;text-transform:uppercase;margin-bottom:3px}
.cod-box{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-radius:5px;margin-bottom:8px}
.cod-box.cash{background:#111;color:#fff}
.cod-box.prepaid{background:#dcfce7;color:#166534;border:1.5px solid #22c55e}
.cod-lbl{font-size:9px;letter-spacing:1px;text-transform:uppercase;opacity:.75}
.cod-amt{font-size:22px;font-weight:900;letter-spacing:1px}
.cod-currency{font-size:11px;opacity:.7;margin-right:3px}
.notes-row{border:1px dashed #bbb;border-radius:4px;padding:8px 10px;min-height:26px;font-size:9px;color:#bbb;margin-bottom:6px}
.footer-row{display:flex;justify-content:space-between;font-size:8px;color:#aaa;border-top:1px solid #eee;padding-top:5px}
.no-print{text-align:center;margin-bottom:12px;display:flex;gap:6px;justify-content:center;flex-wrap:wrap}
.no-print button,.no-print select{font-size:11px;border-radius:6px;padding:7px 13px;border:1px solid #ddd;cursor:pointer}
@media print{.no-print{display:none}body{padding:0;background:#fff}.label{box-shadow:none}}
</style></head>
<body>
<div class="no-print">
  <button onclick="window.print()" style="background:#111;color:#fff;border-color:#111">\u0637\u0628\u0627\u0639\u0629</button>
  <select onchange="window.location.href='/shipping-label?id=${o.id}&fmt='+this.value">
    <option value="yalidine"${fmt==="yalidine"?" selected":""}>Yalidine Express</option>
    <option value="zr"${fmt==="zr"?" selected":""}>Zr Express</option>
    <option value="maystro"${fmt==="maystro"?" selected":""}>Maystro Delivery</option>
  </select>
  <button onclick="window.close()" style="background:#f5f5f5;color:#333">\u0625\u063a\u0644\u0627\u0642</button>
</div>
<div class="label">
  <div class="hdr">
    <div>
      <div class="brand">${sn}</div>
      <div class="brand-wa">${wa}</div>
    </div>
    <div style="text-align:left">
      <div class="fmt-badge">${fmtLabel}</div>
      <div class="order-id">${_escSrv(o.id)}</div>
      <div class="order-date">${printDate}</div>
    </div>
  </div>
  <div class="bc-wrap">${bc}</div>
  <div class="addresses">
    <div class="addr-box">
      <div class="addr-lbl">\u0627\u0644\u0645\u0631\u0633\u0650\u0644</div>
      <div class="addr-name">${sn}</div>
      <div class="addr-detail">${wa}</div>
    </div>
    <div class="addr-box recv">
      <div class="addr-lbl">\u0627\u0644\u0645\u0633\u062a\u0644\u0650\u0645</div>
      <div class="addr-name">${_escSrv(o.name||"")}</div>
      <div class="addr-detail">
        ${_escSrv(o.phone1||"")}${o.phone2?` / ${_escSrv(o.phone2)}`:""}
        <br>${_escSrv(o.wilaya||"")} \u2014 ${_escSrv(o.commune||"")}
        <br><span style="font-size:9px;color:#888">${_escSrv(o.dlbl||"Stop Desk")}</span>
      </div>
    </div>
  </div>
  <div class="items-row">
    <div class="items-lbl">\u0645\u062d\u062a\u0648\u0649 \u0627\u0644\u0637\u0631\u062f</div>
    ${_escSrv(iL)}
  </div>
  ${isPrepaid
    ?`<div class="cod-box prepaid"><div><div class="cod-lbl">\u0645\u062f\u0641\u0648\u0639 \u0645\u0633\u0628\u0642\u0627</div><div style="font-size:11px;margin-top:2px">CCP \u2014 \u0644\u0627 \u062a\u062d\u0635\u064a\u0644</div></div><div style="font-size:20px;font-weight:900;color:#166534">\u2713 \u0645\u062f\u0641\u0648\u0639</div></div>`
    :`<div class="cod-box cash"><div><div class="cod-lbl">\u0645\u0628\u0644\u063a \u0627\u0644\u062a\u062d\u0635\u064a\u0644 (COD)</div></div><div><span class="cod-currency">\u062f\u062c</span><span class="cod-amt">${codAmt.toLocaleString()}</span></div></div>`
  }
  <div class="notes-row">\u0645\u0644\u0627\u062d\u0638\u0627\u062a: _______________________</div>
  <div class="footer-row">
    <span>${sn} &copy; ${new Date().getFullYear()}</span>
    <span>\u062a\u0627\u0631\u064a\u062e \u0627\u0644\u0637\u0644\u0628: ${printDate}</span>
    <span>${_escSrv(o.id)}</span>
  </div>
</div>
</body></html>`;
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
        const prevQty=prods[i].quantity||999;
        const newQty=_upd.quantity;
        if(newQty<=alertQty&&newQty<prevQty){
          const pname=prods[i].name||"منتج";
          await sendPush(env,
            "تحذير مخزون: "+pname,
            "الكمية المتبقية: "+newQty+" / الحد الأدنى: "+alertQty
          );
          try{
            const sh=await kvGet(env,"stock-history",[]);
            sh.unshift({t:new Date().toISOString(),productId:prods[i].id,name:pname,from:prevQty,to:newQty,reason:"alert",alert:true});
            await kvSet(env,"stock-history",sh.slice(0,1000));
          }catch{}}}
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
        /* ── حماية من spam الطلبيات ── */
        const orderFp="ofp:"+getFP(request);
        const orderRl=await kvGet(env,orderFp,{c:0,t:0});
        const now=Date.now();
        if(orderRl.t&&now-orderRl.t<60000&&orderRl.c>=5)
          return RR({error:"الرجاء الانتظار قبل إرسال طلبية أخرى"},429);

        const body=await request.json();
        if(!body.name||!body.phone1||!body.phone2||!body.wilaya||!body.commune||!body.items?.length)
          return RR({error:"Missing fields"},400);
        if(body.phone1===body.phone2)return RR({error:"Phones must differ"},400);
        /* ── التحقق من صيغة الهاتف ── */
        const phoneRx=/^0[567]\d{8}$/;
        if(!phoneRx.test(body.phone1.replace(/\s/g,""))||!phoneRx.test(body.phone2.replace(/\s/g,"")))
          return RR({error:"رقم الهاتف غير صالح"},400);
        /* ── التحقق من عدد المنتجات ── */
        if(body.items.length>20)return RR({error:"عدد المنتجات كبير جداً"},400);

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
          if(isNaN(itemQty))return RR({error:"كمية غير صالحة"},400);
          const prod=prodsData.find(p=>p.id===item.id);
          if(!prod)return RR({error:"المنتج غير موجود: "+item.id},400);
          if(prod.quantity!==null&&prod.quantity!==undefined){
            if(itemQty>prod.quantity)
              return RR({error:"الكمية غير متوفرة للمنتج "+prod.name},400);
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

        /* ── تحديث الكمية مع double-check قبل حفظ الطلبية ── */
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

        // ── خصم الإحالة ──
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
        // ── كوبون الخصم ──
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
        // ── م11: فحص التكرار — هاتف أو (ولاية+بلدية) خلال 48 ساعة ──
        const allOrders=await kvGet(env,"orders",[]);
        const now48=Date.now()-172800000;
        const _samePhone=(x)=>(
          (o.phone1&&(x.phone1===o.phone1||x.phone2===o.phone1))||
          (o.phone2&&(x.phone1===o.phone2||x.phone2===o.phone2))
        );
        const _sameAddr=(x)=>(
          o.wilaya&&o.commune&&x.wilaya&&x.commune&&
          x.wilaya.trim()===o.wilaya.trim()&&
          x.commune.trim()===o.commune.trim()
        );
        const prev=allOrders.find(x=>
          x.id!==o.id&&
          new Date(x.date).getTime()>now48&&
          (_samePhone(x)||_sameAddr(x))
        );
        if(prev){
          o.repeated=true;
          o.prevOrderId=prev.id;
          o.prevOrderDate=prev.date;
          o.repeatGapHours=Math.round((Date.now()-new Date(prev.date).getTime())/3600000);
          o.repeatReason=_samePhone(prev)?"phone":"address";
        }
        o.refDisc=refDisc;o.total=(o.total||total)-refDisc;
        // ── نقاط الولاء (1 نقطة لكل 100 دج) ──
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

        if(o.repeated)await sendPush(env,"طلبية مكررة","هاتف: "+o.phone1+" | "+o.wilaya);else await sendPush(env,"طلبية جديدة ","من: "+o.name+" | "+o.wilaya+" | "+o.total.toLocaleString()+" دج");
        return RR({ok:true,orderId:o.id,total:o.total,finalSub,fee,discAmt,ccpDisc,couponDisc,globalDiscount:appliedGlobalDisc});
      }
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="GET")return RR(await kvGet(env,"orders",[]));
      if(method==="PATCH"){
        const body=await request.json(),orders=await kvGet(env,"orders",[]);
        const i=orders.findIndex(o=>o.id===body.id);
        if(i<0)return RR({error:"Not found"},404);
        const ts=new Date().toISOString();
        const hist=orders[i].history||[];
        /* م12: Audit Trail */
        const _ae={t:ts,changes:[]};
        if(body.status!==undefined&&body.status!==orders[i].status)_ae.changes.push({f:"status",from:orders[i].status,to:body.status});
        if(body.confirmed!==undefined&&body.confirmed!==orders[i].confirmed)_ae.changes.push({f:"confirmed",from:orders[i].confirmed,to:body.confirmed});
        if(body.note!==undefined&&body.note!==orders[i].note)_ae.changes.push({f:"note"});
        if(_ae.changes.length){
          if(!orders[i].auditLog)orders[i].auditLog=[];
          orders[i].auditLog.unshift(_ae);
          orders[i].auditLog=orders[i].auditLog.slice(0,20);
        }
        if(body.status){
          if(orders[i].status!==body.status){
            hist.push({t:ts,txt:"حالة: "+orders[i].status+" ← "+body.status});
            await logActivity(env,"order_status",orders[i].id+": "+body.status);
          }
          orders[i].status=body.status;
        }
        if(body.confirmed!==undefined)orders[i].confirmed=body.confirmed;
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
        const tierBreakdown={
          high:Object.entries(visMap).filter(([,v])=>v.tier==="high").length,
          mid:Object.entries(visMap).filter(([,v])=>v.tier==="mid").length,
          low:Object.entries(visMap).filter(([,v])=>v.tier==="low").length
        };
        const browserMap={};
        visits.forEach(v=>{if(v.browser)browserMap[v.browser]=(browserMap[v.browser]||0)+1;});
        return RR({totalVisits:visits.length,uniqueVisitors:uniq,totalOrders:orders.length,confirmedOrders:conf,
          revenue:rev,netRevenue,totalReturnCost,returnedCount:returnedOrders.length,productCount:prods.length,
          devMap,brandMap,tierMap,osMap,hourMap,browserMap,tierBreakdown,bounceRate,confirmRate,avgOrderVal,
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

    /* ── KV STATS — تقدير المساحة المستخدمة ── */
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



    // ══ FLASH SALES ══════════════════════════════════════════════════
    if(path==="/api/flash-sales"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="GET")return RR(await kvGet(env,"flash_sales",[]));
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        const fs=await kvGet(env,"flash_sales",[]);
        const discVal=Math.min(90,Math.max(0,parseFloat(b.discVal)||0));
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

    // ══ BUNDLES ═══════════════════════════════════════════════════════
    if(path==="/api/bundles"){
      if(method==="GET")return RR(await kvGet(env,"bundles",[]));
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        const bundles=await kvGet(env,"bundles",[]);
        const discVal=Math.min(90,Math.max(0,parseFloat(b.discVal)||0));
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

    // ══ WAITLIST ══════════════════════════════════════════════════════
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
        return RR({ok:true,msg:"سيتم تنبيهك حين يتوفر المنتج"});
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

    // ══ LOYALTY POINTS ════════════════════════════════════════════════
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

    // ══ REFERRALS ════════════════════════════════════════════════════
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

    // ══ REVIEWS ══════════════════════════════════════════════════════
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
        return RR({ok:true,msg:"تم إرسال تقييمك وسيظهر بعد المراجعة"});
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

    // ══ TESTIMONIALS ═════════════════════════════════════════════════
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

    // ══ ABOUT PAGE ══════════════════════════════════════════════════
    if(path==="/about"){
      const sets=await kvGet(env,"settings",{storeName:"WOW Store"});
      const about=sets.about||"";
      return RR(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>عن ${_escSrv(sets.storeName||"WOW Store")}</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0016;color:#e0d0ff;padding:20px;min-height:100vh}.wrap{max-width:680px;margin:0 auto;padding:30px 0}.brand{font-family:Georgia,serif;font-size:40px;font-weight:900;letter-spacing:7px;color:#c084fc;text-align:center;margin-bottom:8px}.sub{text-align:center;font-size:11px;color:rgba(255,255,255,.25);letter-spacing:4px;margin-bottom:40px}.body{font-size:14px;line-height:2;color:rgba(255,255,255,.65)}.back{display:inline-block;margin-bottom:24px;color:rgba(168,85,247,.7);font-size:12px;cursor:pointer;text-decoration:none;border:1px solid rgba(168,85,247,.2);padding:6px 14px;border-radius:7px}
/* ══ FLASH SALE BADGE ══ */
.flash-badge{display:inline-flex;align-items:center;gap:4px;background:linear-gradient(135deg,rgba(239,68,68,.15),rgba(251,191,36,.1));border:1px solid rgba(239,68,68,.3);color:rgba(252,165,165,.9);font-size:9px;font-weight:700;padding:2px 7px;border-radius:4px;letter-spacing:.5px}
.flash-timer{font-size:9px;color:rgba(251,191,36,.8);letter-spacing:.5px;margin-top:2px}
.card-flash-strip{position:absolute;top:0;left:0;right:0;background:linear-gradient(135deg,rgba(239,68,68,.15),rgba(251,191,36,.08));border-bottom:1px solid rgba(239,68,68,.2);padding:3px 8px;font-size:9px;color:rgba(252,165,165,.9);letter-spacing:.5px;font-weight:700;z-index:5;display:flex;justify-content:space-between;align-items:center}

/* ══ BUNDLE CARD ══ */
.bundle-card{background:rgba(109,40,217,.06);border:1px solid rgba(109,40,217,.2);border-radius:14px;padding:16px;cursor:pointer;transition:border-color .2s}
.bundle-card:hover{border-color:rgba(168,85,247,.4)}
.bundle-imgs{display:flex;gap:5px;margin-bottom:10px}
.bundle-img{width:52px;height:64px;object-fit:cover;border-radius:7px;border:1px solid rgba(168,85,247,.1)}
.bundle-name{font-size:13px;font-weight:600;color:rgba(192,132,252,.9);margin-bottom:4px}
.bundle-disc-badge{display:inline-block;background:rgba(74,222,128,.12);border:1px solid rgba(74,222,128,.25);color:rgba(74,222,128,.9);font-size:10px;font-weight:700;padding:2px 8px;border-radius:5px}

/* ══ TESTIMONIAL CARD ══ */
.tcard{background:rgba(255,255,255,.025);border:1px solid rgba(168,85,247,.1);border-radius:12px;padding:16px;min-width:220px;max-width:260px;flex-shrink:0}
.tcard-stars{color:#f59e0b;font-size:13px;margin-bottom:7px}
.tcard-body{font-size:11px;color:rgba(255,255,255,.6);line-height:1.7;margin-bottom:10px}
.tcard-name{font-size:10px;color:rgba(168,85,247,.7);font-weight:600}

/* ══ WAITLIST BTN ══ */
.waitlist-btn{display:block;width:100%;padding:9px;background:rgba(255,255,255,.04);border:1px dashed rgba(168,85,247,.2);border-radius:10px;color:rgba(192,132,252,.6);font-size:11px;cursor:pointer;text-align:center;transition:.2s}
.waitlist-btn:hover{background:rgba(168,85,247,.06);border-color:rgba(168,85,247,.3)}

/* ══ STAR RATING ══ */
.rv-star-on{opacity:1!important}

/* ══ LOYALTY BADGE ══ */
.loyalty-pts-badge{display:inline-flex;align-items:center;gap:5px;background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.2);color:rgba(251,191,36,.9);font-size:10px;padding:4px 10px;border-radius:20px}

/* ══ FLASH SALE ADMIN ROW ══ */
.fs-row{display:grid;grid-template-columns:1fr auto auto auto;gap:10px;align-items:center;padding:9px 12px;border:1px solid rgba(239,68,68,.15);border-radius:9px;margin-bottom:6px;background:rgba(239,68,68,.04);font-size:11px}
.bundle-row{display:grid;grid-template-columns:1fr auto auto auto;gap:10px;align-items:center;padding:9px 12px;border:1px solid rgba(109,40,217,.15);border-radius:9px;margin-bottom:6px;background:rgba(109,40,217,.04);font-size:11px}

/* ══ REVIEW CARD ══ */
.rv-card{padding:11px 13px;border:1px solid var(--b1);border-radius:9px;margin-bottom:7px;background:rgba(255,255,255,.02)}
.rv-card-stars{font-size:12px;color:#f59e0b;margin-bottom:4px}
.rv-card-body{font-size:11px;color:var(--dim);line-height:1.6;margin-bottom:6px}
.rv-card-name{font-size:10px;color:var(--mu)}
.rv-pending{opacity:.5;border-style:dashed}

/* ══ SALES COUNTER ══ */
.sales-counter{font-size:10px;color:rgba(74,222,128,.7);margin-top:3px;letter-spacing:.3px}


/* ══ DRAG AND DROP (م43) ══ */
.aprd-row[draggable]{cursor:grab}
.aprd-row.drag-over{background:rgba(168,85,247,.08);border-color:rgba(168,85,247,.3);outline:2px dashed rgba(168,85,247,.35)}
.aprd-row.dragging{opacity:.4}

/* ══ STORY CARD ══ */
.story-card{background:rgba(255,255,255,.02);border:1px solid var(--b1);border-radius:10px;overflow:hidden;margin-bottom:10px}
.story-card img{width:100%;height:120px;object-fit:cover}
.story-card-body{padding:10px}
.story-title{font-size:13px;font-weight:600;color:rgba(192,132,252,.9);margin-bottom:5px}
.story-excerpt{font-size:11px;color:var(--mu);line-height:1.5}

/* ══ TRUST BADGES BAR ══ */
.trust-badges{display:flex;flex-wrap:wrap;justify-content:center;gap:12px;padding:10px 14px;border-top:1px solid rgba(255,255,255,.05)}
.trust-badge{display:flex;align-items:center;gap:5px;font-size:10px;color:rgba(255,255,255,.35);letter-spacing:.5px}

/* ══ FAQ ACCORDION ══ */
.faq-item{border-bottom:1px solid rgba(255,255,255,.06)}
.faq-q{padding:11px 14px;cursor:pointer;font-size:12px;color:rgba(192,132,252,.8);font-weight:600;display:flex;justify-content:space-between;align-items:center;list-style:none}
.faq-a{padding:0 14px 11px;font-size:11px;color:rgba(255,255,255,.5);line-height:1.7}

/* ══ QR CODE ══ */
.qr-modal-wrap{text-align:center;padding:16px 0}
.qr-wrap{display:inline-block;padding:12px;background:#fff;border-radius:10px;margin:0 auto}

/* ══ PRODUCT LANGUAGE TABS ══ */
.lang-tab{display:inline-flex;gap:0;margin-bottom:10px;border:1px solid var(--b1);border-radius:7px;overflow:hidden}
.lang-tab-btn{padding:5px 14px;font-size:10px;cursor:pointer;background:transparent;border:none;color:var(--mu);transition:.15s}
.lang-tab-btn.on{background:rgba(168,85,247,.12);color:rgba(192,132,252,.9)}

/* ══ SCHEDULED BADGE ══ */
.scheduled-badge{display:inline-flex;align-items:center;gap:4px;background:rgba(99,102,241,.1);border:1px solid rgba(99,102,241,.25);color:rgba(165,180,252,.8);font-size:9px;padding:2px 7px;border-radius:4px}

/* ══ VARIANTS GRID ══ */
.variants-grid{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.var-chip{padding:5px 12px;background:rgba(255,255,255,.04);border:1px solid rgba(168,85,247,.15);border-radius:20px;font-size:11px;color:var(--dim);cursor:pointer;transition:.15s}
.var-chip:hover,.var-chip.on{background:rgba(168,85,247,.12);border-color:rgba(168,85,247,.4);color:rgba(192,132,252,.9)}

</style></head><body><div class="wrap"><a class="back" href="/">&#8594; العودة للمتجر</a><div class="brand">${_escSrv(sets.storeName||"WOW STORE")}</div><div class="sub">ABOUT US</div><div class="body">${about.replace(/\n/g,"<br>")}</div></div></body></html>`,200,{"Content-Type":"text/html;charset=utf-8"});
    }


    // ══ PRODUCT DEEP LINK /p/:id (م29) ══════════════════════════════
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

    // ══ ARCHIVED PRODUCTS ═══════════════════════════════════════════
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

    // ══ COUPONS ══════════════════════════════════════════════════════
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
        if(discType==="percent")discVal=Math.min(90,discVal);
        else discVal=Math.min(500,discVal);
        const c={id:Date.now(),code,discType,discVal,maxUses:b.maxUses?parseInt(b.maxUses)||0:0,
          minCart:b.minCart?parseFloat(b.minCart)||0:0,
          wilayaList:Array.isArray(b.wilayaList)&&b.wilayaList.length?b.wilayaList:[],
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

    // ══ COUPON CHECK (public) ════════════════════════════════════════
    if(path==="/api/coupon-check"&&method==="POST"){
      const{code,sub,wilaya}=await request.json().catch(()=>({}));
      if(!code)return RR({ok:false,msg:"أدخل كود الخصم"});
      const coupons=await kvGet(env,"coupons",[]);
      const c=coupons.find(x=>x.code===(code||"").toUpperCase()&&x.active);
      if(!c)return RR({ok:false,msg:"الكود غير صالح"});
      if(c.expiresAt&&Date.now()>new Date(c.expiresAt).getTime())return RR({ok:false,msg:"الكود منتهي الصلاحية"});
      if(c.maxUses>0&&c.usedCount>=c.maxUses)return RR({ok:false,msg:"تم استنفاد هذا الكود"});
      /* م5: minCart check */
      const orderSub=parseFloat(sub)||0;
      if(c.minCart&&c.minCart>0&&orderSub<c.minCart)
        return RR({ok:false,msg:"الحد الأدنى للسلة: "+c.minCart.toLocaleString()+" دج"});
      /* م5: wilaya restriction */
      if(c.wilayaList&&c.wilayaList.length&&wilaya&&!c.wilayaList.includes(wilaya))
        return RR({ok:false,msg:"هذا الكوبون غير متاح في ولايتك"});
      let discAmt=0;
      if(c.discType==="percent")discAmt=Math.round(orderSub*(c.discVal/100));
      else discAmt=Math.min(c.discVal,orderSub);
      return RR({ok:true,code:c.code,discType:c.discType,discVal:c.discVal,discAmt,
        msg:"تم تطبيق الخصم"});
    }

    // ══ STOCK HISTORY ════════════════════════════════════════════════
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

    // ══ ACTIVITY LOG ════════════════════════════════════════════════
    if(path==="/api/activity-log"&&method==="GET"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      return RR(await kvGet(env,"activity_log",[]));
    }

    // ══ INVOICE PAGE ════════════════════════════════════════════════
    if(path==="/invoice"&&method==="GET"){
      if(!await isAdmin(request,env))return RR("Unauthorized",401);
      const oid=url.searchParams.get("id");if(!oid)return RR("Missing id",400);
      const orders=await kvGet(env,"orders",[]);const o=orders.find(x=>x.id===oid);
      if(!o)return RR("Not found",404);
      const sets=await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:""});
      const opts={
        hideShipping:url.searchParams.get("hideShip")==="true",
        extraNote:url.searchParams.get("note")||"",
        scale:parseFloat(url.searchParams.get("scale")||"1"),
        printTracked:url.searchParams.get("pt")==="1"
      };
      /* تتبع وقت الطباعة في سجل الطلب */
      if(opts.printTracked){
        const idx=orders.findIndex(x=>x.id===oid);
        if(idx>=0){
          if(!orders[idx].printLog)orders[idx].printLog=[];
          orders[idx].printLog.push(new Date().toISOString());
          await kvSet(env,"orders",orders);
        }
      }
      return new Response(buildInvoiceHTML(o,sets,opts),{headers:{"Content-Type":"text/html;charset=utf-8","Cache-Control":"no-cache"}});
    }

    // ══ SHIPPING LABEL PAGE ═════════════════════════════════════════
    if(path==="/shipping-label"&&method==="GET"){
      if(!await isAdmin(request,env))return RR("Unauthorized",401);
      const oid=url.searchParams.get("id");const fmt=url.searchParams.get("fmt")||"yalidine";
      if(!oid)return RR("Missing id",400);
      const orders=await kvGet(env,"orders",[]);const o=orders.find(x=>x.id===oid);
      if(!o)return RR("Not found",404);
      const sets=await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322"});
      return new Response(buildShippingLabel(o,sets,fmt),{headers:{"Content-Type":"text/html;charset=utf-8","Cache-Control":"no-cache"}});
    }


    // ══ PRODUCT REORDER (م43) ═══════════════════════════════════════
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

    // ══ STORIES (م48) ════════════════════════════════════════════════
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

    // ══ STORIES PAGE ═════════════════════════════════════════════════
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

    // ══ API DOCS (م49) ════════════════════════════════════════════════
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
].map(([m,p,d,a])=>`<div class="ep"><span class="method ${m.toLowerCase().split('/')[0]==='get'?'get':m.toLowerCase().split('/')[0]==='post'?'post':m.toLowerCase().split('/')[0]==='patch'?'patch':'del'}">${m}</span><span class="path">${p}</span><div class="desc">${d}</div><div class="auth">${a}</div></div>`).join("")}
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

<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#050505;--p1:rgba(255,255,255,.04);--b1:rgba(255,255,255,.08);--ac:#a855f7;--tx:rgba(255,255,255,.88);--dim:rgba(255,255,255,.4);--mu:rgba(255,255,255,.22);--r:16px;--rs:10px}
html,body{touch-action:pan-y;-ms-touch-action:pan-y}
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
.ambient-bg{position:fixed;inset:0;pointer-events:none;z-index:-1;background:radial-gradient(ellipse 75% 55% at 30% 40%,rgba(88,28,135,.05),transparent 60%),radial-gradient(ellipse 55% 45% at 70% 60%,rgba(55,48,163,.035),transparent 55%); isolation: isolate;}
.ambient-bg2{display:none}
.mist{display:none}.mist3{display:none}.grad-overlay{display:none}

/* ══ VOID GLITCH ENTITY ══ */
#void-glitch{position:fixed;pointer-events:none;z-index:-1;mix-blend-mode:screen;will-change:transform,opacity}
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
.grid{max-width:1200px;margin:0 auto;padding:0 20px 100px;display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:14px;position:relative;z-index:5;min-height:400px}

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
.card{background:rgba(10,5,18,.96);border:1px solid rgba(168,85,247,.1);border-radius:var(--r);overflow:hidden;display:flex;flex-direction:column;cursor:pointer;transition:transform .22s ease,box-shadow .22s ease,border-color .22s ease;position:relative;contain: content;}
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
.img-slider{position:relative;overflow:hidden;aspect-ratio:3/4;background:#0a0016;transition:box-shadow .3s;border-radius:var(--r) var(--r) 0 0;contain: strict;}
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

/* == CONFIRM-MOD m3 == */
.confirm-mod{background:rgba(8,4,20,.98);border:1px solid rgba(239,68,68,.3);border-radius:16px;padding:24px 20px;max-width:340px;width:90%;animation:pop .32s cubic-bezier(.34,1.56,.64,1)}
.confirm-mod-title{font-family:Georgia,serif;font-size:13px;color:rgba(239,68,68,.9);letter-spacing:2px;text-transform:uppercase;margin-bottom:6px}
.confirm-mod-info{font-size:11px;color:rgba(255,255,255,.5);line-height:1.7;margin-bottom:14px;padding:9px 11px;background:rgba(239,68,68,.05);border:1px solid rgba(239,68,68,.1);border-radius:8px;white-space:pre-line}
.confirm-mod-label{font-size:10px;color:rgba(255,255,255,.35);letter-spacing:1px;margin-bottom:5px;display:block}
.confirm-mod-inp{width:100%;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:8px;color:rgba(255,255,255,.8);font-size:12px;padding:8px 10px;outline:none;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;margin-bottom:12px;box-sizing:border-box;transition:.18s}
.confirm-mod-inp:focus{border-color:rgba(239,68,68,.5)}
.confirm-mod-btns{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:4px}
.confirm-mod-cancel{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:9px;padding:9px;font-size:11px;color:rgba(255,255,255,.45);cursor:pointer;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;transition:.18s}
.confirm-mod-cancel:hover,.confirm-mod-cancel:active{border-color:rgba(255,255,255,.22);color:rgba(255,255,255,.7)}
.confirm-mod-del-wrap{position:relative}
.confirm-mod-del{background:rgba(239,68,68,.14);border:1px solid rgba(239,68,68,.3);border-radius:9px;padding:9px;font-size:11px;color:rgba(239,68,68,.8);cursor:pointer;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;transition:background .18s,border-color .18s;width:100%;user-select:none;-webkit-tap-highlight-color:transparent;overflow:hidden}
.confirm-mod-del.ready{background:rgba(239,68,68,.28);border-color:rgba(239,68,68,.6);color:rgba(239,68,68,1)}
.confirm-hold-bar{position:absolute;bottom:0;right:0;height:3px;background:rgba(239,68,68,.7);width:0;border-radius:0 0 9px 9px;pointer-events:none}
.confirm-mod-arch{background:rgba(168,85,247,.1);border:1px solid rgba(168,85,247,.25);border-radius:9px;padding:9px;font-size:11px;color:rgba(192,132,252,.8);cursor:pointer;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;transition:.18s;margin-bottom:8px;width:100%;display:block;text-align:center}
.confirm-mod-arch:hover,.confirm-mod-arch:active{background:rgba(168,85,247,.2);border-color:rgba(168,85,247,.45)}

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

/* == SALES CHART m15 == */
#sales-chart svg{display:block}
#sales-chart circle{cursor:pointer;transition:r .15s}
#sales-chart circle:hover{r:6}
#algeria-map-c svg{display:block;margin:0 auto}
#algeria-map-c circle{cursor:pointer;transition:r .15s,fill .2s}

/* == TESTIMONIALS SLIDER m30 == */
#testimonials-slider{display:flex;overflow-x:hidden;scroll-snap-type:x mandatory;scroll-behavior:smooth}
.tm-slide{flex:0 0 100%;scroll-snap-align:start;padding:18px 20px;background:rgba(168,85,247,.04);border:1px solid rgba(168,85,247,.1);border-radius:12px;box-sizing:border-box}
.tm-stars{margin-bottom:8px;font-size:16px}
.tm-body{font-size:13px;color:rgba(255,255,255,.7);line-height:1.7;margin-bottom:10px;font-style:italic}
.tm-name{font-size:11px;color:rgba(168,85,247,.7);letter-spacing:1px}

/* == QR WINDOW m29 == */
.qr-wrap{display:inline-block;padding:14px;background:#fff;border-radius:10px}

/* == BULK PRINT m13 == */
#bulk-print-btn:disabled{opacity:.4;cursor:not-allowed}
.ord-chk{flex-shrink:0;cursor:pointer}
/* == MARGIN PREVIEW m37 == */
#p-margin-preview{transition:color .2s}

/* == WILAYA ACCORDION m10 == */
.wly-acc summary::-webkit-details-marker{display:none}
.wly-acc summary{-webkit-tap-highlight-color:transparent}

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



.sz-oos{opacity:.35;cursor:not-allowed;text-decoration:line-through;pointer-events:none}
/* ══ PHASE 1 — TOUCH EVENTS: no 300ms delay, instant response ══ */
button,
.btn-main,
.aact,
.sz-btn,
.bn-item,
.xbtn,
.anav,
.pill,
.pay-opt,
.cats-pill,
[onclick],
label[for],
.footer-link,
.arch-row button,
.coup-row button,
.fs-row button,
.rv-card button,
.ord-chk,
.arch-chk {
  touch-action: manipulation;
  -webkit-tap-highlight-color: transparent;
  cursor: pointer;
}
/* Prevent ghost click on fast taps */
.xbtn,.aact,.btn-main,.sz-btn,.bn-item,.anav {
  user-select: none;
  -webkit-user-select: none;
}
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
          <filter id="wn" x="-15%" y="-15%" width="130%" height="130%">
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
            <filter id="fn" x="-15%" y="-15%" width="130%" height="130%">
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
              <div class="pay-opt-title">الدفع عند الاستلام</div>
              <div class="pay-opt-sub">ادفع نقداً حين وصول طلبيتك — مجاني</div>
            </div>
          </label>
          <label class="pay-opt" id="pay-ccp-lbl">
            <input type="radio" name="pay-method" id="pay-ccp" value="ccp">
            <div class="pay-opt-body">
              <div class="pay-opt-title">الدفع المسبق بـ CCP</div>
              <div class="pay-opt-sub">تحويل بريدي مسبق — خصم 50 دج على التوصيل</div>
            </div>
          </label>
          <div id="ccp-details" style="display:none;background:rgba(168,85,247,.07);border:1px solid rgba(168,85,247,.2);border-radius:10px;padding:11px 13px;font-size:11px;color:rgba(255,255,255,.65);line-height:1.8">
            <div style="font-size:10px;color:rgba(168,85,247,.7);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px">تفاصيل الحساب البريدي</div>
            <div>رقم الحساب: <span style="color:rgba(192,132,252,.9);font-family:Georgia,serif">0023456789 01</span></div>
            <div>الاسم: <span style="color:rgba(255,255,255,.8)">WOW STORE</span></div>
            <div style="margin-top:7px;font-size:10px;color:rgba(251,191,36,.7)">ارسل صورة الإيصال عبر الواتساب بعد التحويل</div>
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
        <div class="fl"><label>كود خصم (اختياري)</label>
          <div style="display:flex;gap:6px">
            <input class="inp" id="o-coupon" type="text" placeholder="مثال: SAVE10" style="text-transform:uppercase;font-size:11px;flex:1" autocomplete="off" autocapitalize="characters">
            <button class="aact e" style="font-size:11px;white-space:nowrap;touch-action:manipulation" onclick="WOW._applyCoupon()">تطبيق</button>
          </div>
          <div id="coupon-status" style="font-size:10px;color:var(--mu);min-height:14px;margin-top:3px"></div>
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
    <div class="mod-title">أضف تقييمك<button class="xbtn" id="review-xbtn">✕</button></div>
    <div id="review-prod-name" style="font-size:11px;color:var(--mu);margin-bottom:12px"></div>
    <div class="fl"><label>اسمك</label><input class="inp" id="rv-name" placeholder="أحمد م."></div>
    <div class="fl"><label>رقم هاتفك (للتحقق)</label><input class="inp" id="rv-phone" type="tel" placeholder="0661234567"></div>
    <div class="fl"><label>التقييم</label>
      <div style="display:flex;gap:8px;margin-top:4px" id="rv-stars">
        <span data-star="1" style="font-size:24px;cursor:pointer;opacity:.4">⭐</span>
        <span data-star="2" style="font-size:24px;cursor:pointer;opacity:.4">⭐</span>
        <span data-star="3" style="font-size:24px;cursor:pointer;opacity:.4">⭐</span>
        <span data-star="4" style="font-size:24px;cursor:pointer;opacity:.4">⭐</span>
        <span data-star="5" style="font-size:24px;cursor:pointer;opacity:.4">⭐</span>
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

<!-- CONFIRM-MOD m3 -->
<div class="mod-ov" id="confirm-mod" style="display:none">
  <div class="confirm-mod">
    <div class="confirm-mod-title">تاكيد العملية</div>
    <div class="confirm-mod-info" id="confirm-mod-info"></div>
    <button class="confirm-mod-arch" id="confirm-mod-archive-btn">ارشفة المنتج (يمكن استعادته لاحقا)</button>
    <label class="confirm-mod-label">اكتب "حذف" لتفعيل الحذف النهائي</label>
    <input class="confirm-mod-inp" id="confirm-mod-inp" type="text" placeholder="حذف" autocomplete="off">
    <div class="confirm-mod-btns">
      <button class="confirm-mod-cancel" id="confirm-mod-cancel">الغاء</button>
      <div class="confirm-mod-del-wrap">
        <button class="confirm-mod-del" id="confirm-mod-del-btn">اضغط مطولا للحذف</button>
        <div class="confirm-hold-bar" id="confirm-hold-bar"></div>
      </div>
    </div>
  </div>
</div>

<!-- ADMIN PANEL -->
<div id="adm">
  <div class="adm-hdr">
    <div class="adm-logo">
      <svg width="52" height="20" viewBox="0 0 340 133" xmlns="http://www.w3.org/2000/svg" style="overflow:visible;opacity:.8">
        <defs>
          <filter id="an" x="-15%" y="-15%" width="130%" height="130%">
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
      <div id="adm-hdr-actions" style="display:flex;gap:5px;align-items:center"><a href="/api-docs" target="_blank" class="aact" style="font-size:9px;text-decoration:none;padding:4px 8px" title="API Docs">API</a><button onclick="window._showHeatmap&&window._showHeatmap()" class="aact" style="font-size:9px;padding:4px 7px">خريطة</button><button onclick="WOW._toggleFullscreen()" class="aact" style="font-size:11px;padding:4px 7px" title="F11">▣</button></div><button class="xbtn" id="adm-close-btn" style="width:auto;padding:6px 12px;font-size:11px">&#8592; خروج</button>
    </div>
  </div>
  <div class="adm-body">
    <div class="adm-side">
      <div class="anav on" data-tab="analytics">Analytics</div>
      <div class="anav" data-tab="products">Products</div>
      <div class="anav" data-tab="addprod">Add Product</div>
      <div class="anav" data-tab="orders">Orders</div>
      <div class="anav" data-tab="coupons">Coupons</div>
      <div class="anav" data-tab="archive">Archive</div>
      <div class="anav" data-tab="stock">Stock</div>
      <div class="anav" data-tab="visitors">Visitors</div>
      <div class="anav" data-tab="activity">Activity</div>
      <div class="anav" data-tab="flash">Flash Sale</div>
      <div class="anav" data-tab="bundles">Bundles</div>
      <div class="anav" data-tab="waitlist">Waitlist</div>
      <div class="anav" data-tab="loyalty">Loyalty</div>
      <div class="anav" data-tab="referrals">Referrals</div>
      <div class="anav" data-tab="reviews">Reviews</div>
      <div class="anav" data-tab="testimonials">Testimonials</div>
      <div class="anav" data-tab="stories">Stories</div>
      <div class="anav" data-tab="settings">Settings</div>
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
        <div class="cw"><div class="cl" style="display:flex;justify-content:space-between"><span>المبيعات — آخر 14 يوم</span><span id="sales-chart-total" style="font-size:11px;color:rgba(168,85,247,.7)"></span></div><div id="sales-chart" style="margin-top:8px;overflow-x:auto"></div></div>
        <div class="cw"><div class="cl">Device Brands</div><div id="brand-chart"></div></div>
        <div class="cw"><div class="cl">Device Types</div><div id="dev-chart"></div></div>
        <div class="cw"><div class="cl">Visit Hours (24h)</div><div id="hr-chart"></div></div>
        <div class="cw"><div class="cl">أفضل الولايات</div><div id="wilaya-chart"></div></div>
        <div class="cw" style="grid-column:1/-1"><div class="cl">خريطة الجزائر — توزيع الطلبيات</div><div id="algeria-map-c" style="overflow-x:auto;margin-top:6px"></div></div>
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
          <div style="font-size:10px;color:rgba(168,85,247,.6);letter-spacing:1px;margin-bottom:8px">المقاسات والألوان (م26)</div>
          <div class="fl" style="margin-bottom:6px"><label>المقاسات (فاصلة)</label><input class="inp" id="s-sizes" placeholder="XS,S,M,L,XL,XXL"></div>
          <div class="fl" style="margin-bottom:0"><label>الألوان</label><input class="inp" id="s-colors" placeholder="أبيض,أسود,أزرق"></div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px">
          <div class="fl" style="margin:0"><label>تنبيه مخزون عند (م27)</label><input class="inp" id="s-alertqty" type="number" placeholder="5" min="0"></div>
          <div class="fl" style="margin:0"><label>تاريخ الظهور (م28)</label><input class="inp" id="s-showat" type="datetime-local"></div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px">
          <div class="fl" style="margin:0"><label>سعر التكلفة (مط37) دج</label><input class="inp" id="p-cost" type="number" placeholder="0" min="0" style="width:100%"></div>
          <div class="fl" style="margin:0"><label>هامش الربح المتوقع</label><input class="inp" id="p-margin-preview" type="text" readonly placeholder="--" style="opacity:.55;width:100%"></div>
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
            <button class="aact" onclick="WOW._exportCSV()" style="background:rgba(34,197,94,.12);border-color:rgba(34,197,94,.3);color:rgba(134,239,172,.9)">تصدير CSV</button>
          <button class="aact" onclick="WOW._showCsvCols()" style="font-size:9px">أعمدة</button>
            <button class="aact d" id="orders-clear-btn">Clear All</button>
          </div>
        </div>
        <div id="ord-f-bar" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px;padding:9px;background:rgba(255,255,255,.02);border-radius:8px;border:1px solid var(--b1)">
          <input class="inp" id="ord-f-q" placeholder="بحث: اسم ، رقم طلبية..." style="flex:1;min-width:110px;font-size:10px;padding:5px 8px">
          <input class="inp" id="ord-f-wilaya" placeholder="الولاية..." style="width:90px;font-size:10px;padding:5px 8px">
          <input class="inp" id="ord-f-phone" placeholder="هاتف..." style="width:90px;font-size:10px;padding:5px 8px">
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
          <select class="inp" id="ord-f-rep" style="font-size:10px;padding:5px 8px;width:auto">
            <option value="">كل الطلبيات</option>
            <option value="1">مكررة فقط</option>
            <option value="0">غير مكررة</option>
          </select>
          <input class="inp" id="ord-f-q" type="text" placeholder="اسم / هاتف / رقم / ولاية / حالة" style="font-size:10px;padding:5px 8px;flex:1;min-width:150px">
          <button class="aact" id="ord-f-clear-btn" style="font-size:10px">مسح</button>
          <button class="aact" onclick="WOW._groupOrders()">بالولاية</button>
        </div>
        <div id="orders-c"></div>
      </div>
      <div class="asec" id="as-visitors">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:7px">
          <div class="adm-title" style="margin-bottom:0">Visitor Tracking</div>
          <button class="aact e" onclick="WOW._loadVisitors()">&#8635; Refresh</button>
        </div>
        <div style="margin-bottom:13px;padding:11px;background:rgba(239,68,68,.05);border:1px solid rgba(239,68,68,.15);border-radius:9px">
          <div style="font-size:10px;color:rgba(252,165,165,.7);letter-spacing:1px;margin-bottom:8px">حذف سجل الزيارات</div>
          <div style="display:flex;flex-wrap:wrap;gap:5px">
            <button class="aact" data-delvis="1h" style="font-size:10px">آخر ساعة</button>
            <button class="aact" data-delvis="6h" style="font-size:10px">آخر 6 ساعات</button>
            <button class="aact" data-delvis="24h" style="font-size:10px">آخر 24 ساعة</button>
            <button class="aact" data-delvis="7d" style="font-size:10px">آخر 7 أيام</button>
            <button class="aact" data-delvis="30d" style="font-size:10px">آخر 30 يوم</button>
            <button class="aact" data-delvis="365d" style="font-size:10px">آخر سنة</button>
            <button class="aact d" data-delvis="all" style="font-size:10px">حذف الكل</button>
          </div>
        </div>
        <div id="visitors-c"></div>
      </div>

      <div class="asec" id="as-coupons">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">Coupons</div>
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
            <div class="fl" style="margin:0"><label>حد أدنى للسلة دج (0=بدون حد)</label><input class="inp" id="cp-min" type="number" placeholder="0"></div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px">
            <div class="fl" style="margin:0"><label>تاريخ الانتهاء</label><input class="inp" id="cp-exp" type="datetime-local"></div>
            <div class="fl" style="margin:0"><label>ولايات محددة (فاصلة، فارغ=كل)</label><input class="inp" id="cp-wilayas" placeholder="الجزائر,وهران"></div>
          </div>
          <button class="btn-main" style="width:auto;padding:8px 18px;font-size:11px" onclick="WOW._createCoupon()">+ إنشاء كوبون</button>
        </div>
        <div id="coupons-c"></div>
      </div>

      <div class="asec" id="as-archive">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">Archived Products</div>
          <button class="aact e" onclick="WOW._loadArchive()">مزامنة</button>
          <button class="aact" id="archive-restore-all-btn" style="display:none" onclick="WOW._restoreSelectedArchive()">استعادة المحدد</button>
          <label style="font-size:10px;color:var(--mu);display:flex;align-items:center;gap:4px">
            <input type="checkbox" id="archive-sel-all" style="accent-color:#a855f7"> تحديد الكل
          </label>
        </div>
        <div id="archive-c"><div style="color:var(--mu);font-size:12px">اضغط Refresh لتحميل المؤرشَف</div></div>
      </div>

      <div class="asec" id="as-stock">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">Stock History</div>
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
          <div class="adm-title" style="margin-bottom:0">Activity Log</div>
          <button class="aact e" onclick="WOW._loadActivity()">&#8635; Refresh</button>
        </div>
        <div id="activity-c"><div style="color:var(--mu);font-size:12px">اضغط Refresh لتحميل السجل</div></div>
      </div>

      <div class="asec" id="as-flash">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">Flash Sales</div>
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
          <button class="btn-main" style="width:auto;padding:8px 18px;font-size:11px" onclick="WOW._createFlashSale()">إنشاء Flash Sale</button>
        </div>
        <div id="flash-c"></div>
      </div>

      <div class="asec" id="as-bundles">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">Bundles</div>
          <button class="aact e" onclick="WOW._loadBundles()">&#8635; Refresh</button>
        </div>
        <div style="background:rgba(255,255,255,.025);border:1px solid var(--b1);border-radius:10px;padding:14px;margin-bottom:14px">
          <div style="font-size:10px;color:rgba(167,139,250,.6);letter-spacing:1px;margin-bottom:10px">إنشاء حزمة جديدة</div>
          <div class="fl" style="margin-bottom:8px"><label>اسم الحزمة</label><input class="inp" id="bd-name" placeholder="حزمة الصيف"></div>
          <div class="fl" style="margin-bottom:8px"><label>المنتجات (أرقام IDs مفصولة بفاصلة)</label><input class="inp" id="bd-prods" placeholder="1234567890,9876543210"></div>
          <div class="fl" style="margin-bottom:10px"><label>خصم الحزمة % (حد 11%)</label><input class="inp" id="bd-disc" type="number" min="1" max="11" placeholder="8"></div>
          <button class="btn-main" style="width:auto;padding:8px 18px;font-size:11px" onclick="WOW._createBundle()">إنشاء حزمة</button>
        </div>
        <div id="bundles-c"></div>
      </div>

      <div class="asec" id="as-waitlist">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">Waitlist</div>
          <button class="aact e" onclick="WOW._loadWaitlist()">&#8635; Refresh</button>
        </div>
        <div id="waitlist-c"><div style="color:var(--mu);font-size:12px">اضغط Refresh</div></div>
      </div>

      <div class="asec" id="as-loyalty">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">نقاط الولاء</div>
          <button class="aact e" onclick="WOW._loadLoyalty()">&#8635; Refresh</button>
        </div>
        <div style="font-size:11px;color:var(--mu);margin-bottom:10px;padding:9px;background:rgba(255,255,255,.02);border-radius:8px;border:1px solid var(--b1)">
          <strong style="color:rgba(251,191,36,.8)">1 نقطة = 100 دج مشتريات</strong> · يمكن استبدال النقاط بخصم في الطلبية القادمة
        </div>
        <div id="loyalty-c"><div style="color:var(--mu);font-size:12px">اضغط Refresh</div></div>
      </div>

      <div class="asec" id="as-referrals">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">Referrals</div>
          <button class="aact e" onclick="WOW._loadReferrals()">&#8635; Refresh</button>
        </div>
        <div style="font-size:11px;color:var(--mu);margin-bottom:10px;padding:9px;background:rgba(255,255,255,.02);border-radius:8px;border:1px solid var(--b1)">
          رابط الإحالة: <code style="color:rgba(192,132,252,.8)">/refer?p=PHONE</code> · الخصم: 5% لكل إحالة ناجحة
        </div>
        <div id="referrals-c"><div style="color:var(--mu);font-size:12px">اضغط Refresh</div></div>
      </div>

      <div class="asec" id="as-reviews">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">تقييمات الزبائن</div>
          <button class="aact e" onclick="WOW._loadReviews()">&#8635; Refresh</button>
        </div>
        <div id="reviews-c"><div style="color:var(--mu);font-size:12px">اضغط Refresh</div></div>
      </div>

      <div class="asec" id="as-testimonials">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">Testimonials</div>
          <button class="aact e" onclick="WOW._loadTestimonials()">&#8635; Refresh</button>
        </div>
        <div style="background:rgba(255,255,255,.025);border:1px solid var(--b1);border-radius:10px;padding:14px;margin-bottom:14px">
          <div style="font-size:10px;color:rgba(167,139,250,.6);letter-spacing:1px;margin-bottom:10px">إضافة شهادة</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px">
            <div class="fl" style="margin:0"><label>الاسم</label><input class="inp" id="tm-name" placeholder="أحمد م."></div>
            <div class="fl" style="margin:0"><label>التقييم</label><select class="inp" id="tm-rating"><option value="5">⭐⭐⭐⭐⭐</option><option value="4">⭐⭐⭐⭐</option><option value="3">⭐⭐⭐</option></select></div>
          </div>
          <div class="fl" style="margin-bottom:10px"><label>الشهادة</label><textarea class="inp" id="tm-body" rows="3" placeholder="رأيه في المتجر..."></textarea></div>
          <button class="btn-main" style="width:auto;padding:8px 18px;font-size:11px" onclick="WOW._createTestimonial()">+ إضافة</button>
        </div>
        <div id="testimonials-c"></div>
      </div>

      
      <!-- STORIES SECTION -->
      <div class="asec" id="as-stories">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">Stories</div>
          <div style="display:flex;gap:6px">
            <a href="/stories" target="_blank" class="aact" style="font-size:10px;text-decoration:none">عرض</a>
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
        <div class="fl"><label>تكلفة الشحن الافتراضية (مط37) دج</label>
          <input class="inp" id="s-ship-cost" type="number" min="0" placeholder="400" style="width:120px">
        <div style="font-size:10px;color:var(--mu);margin-top:3px">تُخصم من صافي كل طلبية في حساب الهامش</div>
        </div>
        <div class="fl"><label>Hero Background (رابط صورة JPG/PNG أو فيديو MP4)</label><input class="inp" id="s-hero" placeholder="https://example.com/banner.jpg"></div>
        <div style="margin-bottom:10px">
          <label style="font-size:10px;color:rgba(168,85,247,.6);display:block;margin-bottom:6px">أو اختر من المعرض مباشرة:</label>
          <label id="hero-pick-lbl" style="display:flex;align-items:center;gap:8px;background:rgba(168,85,247,.08);border:1px dashed rgba(168,85,247,.3);border-radius:10px;padding:10px 12px;cursor:pointer;transition:.2s">
            <span style="font-size:18px; display:none"></span>
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
          <div style="font-size:10px;color:rgba(168,85,247,.6);letter-spacing:1px;margin-bottom:8px">Trust Bar (م38)</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:7px">
            <input class="inp" id="tb1" placeholder="شحن لكل ولايات الجزائر">
            <input class="inp" id="tb2" placeholder="جودة مضمونة">
            <input class="inp" id="tb3" placeholder="إرجاع خلال 7 أيام">
            <input class="inp" id="tb4" placeholder="منتجات أصلية 100%">
          </div>
        </div>
        <!-- FAQ + Refund Policy (م39) -->
        <div style="border-top:1px solid var(--b1);margin:14px 0;padding-top:14px">
          <div style="font-size:10px;color:rgba(168,85,247,.6);letter-spacing:1px;margin-bottom:8px">الأسئلة الشائعة FAQ (م39)</div>
          <textarea class="inp" id="s-faq" rows="4" placeholder="س: كم يستغرق الشحن؟&#10;ج: من 2 إلى 5 أيام عمل.&#10;&#10;س: هل يمكن الإرجاع؟&#10;ج: نعم خلال 7 أيام."></textarea>
        </div>
        <div class="fl" style="margin-bottom:10px"><label>سياسة الإرجاع (م39)</label>
          <textarea class="inp" id="s-refund" rows="3" placeholder="يحق للزبون إرجاع المنتج خلال 7 أيام من الاستلام..."></textarea>
        </div>
        <!-- Trust Badges (م40) -->
        <div style="border-top:1px solid var(--b1);margin:14px 0;padding-top:14px">
          <div style="font-size:10px;color:rgba(168,85,247,.6);letter-spacing:1px;margin-bottom:8px">شارات الثقة (م40)</div>
          <div style="display:flex;flex-wrap:wrap;gap:10px">
            <label style="display:flex;align-items:center;gap:5px;font-size:11px;cursor:pointer"><input type="checkbox" id="badge-ssl"> SSL</label>
            <label style="display:flex;align-items:center;gap:5px;font-size:11px;cursor:pointer"><input type="checkbox" id="badge-cod"> COD</label>
            <label style="display:flex;align-items:center;gap:5px;font-size:11px;cursor:pointer"><input type="checkbox" id="badge-return"> إرجاع</label>
            <label style="display:flex;align-items:center;gap:5px;font-size:11px;cursor:pointer"><input type="checkbox" id="badge-quality"> جودة</label>
            <label style="display:flex;align-items:center;gap:5px;font-size:11px;cursor:pointer"><input type="checkbox" id="badge-fast"> شحن سريع</label>
          </div>
        </div>
        <!-- Language (م44) -->
        <div class="fl" style="margin-bottom:14px"><label>لغة الموقع (م44)</label>
          <select class="inp" id="s-lang">
            <option value="ar">🇩🇿 العربية</option>
            <option value="fr">🇫🇷 Français</option>
            <option value="en">🇬🇧 English</option>
          </select>
        </div>
        <button class="btn-main" id="save-settings-btn">Save Settings</button>
      </div>
    </div>
  </div>
</div>
<!-- KEYBOARD SHORTCUTS HINT (م46) -->
<div id="kb-hint" style="display:none;transition:opacity .28s;position:fixed;bottom:70px;left:50%;transform:translateX(-50%);background:rgba(10,0,22,.97);border:1px solid rgba(168,85,247,.25);border-radius:10px;padding:10px 16px;z-index:9000;font-size:10px;color:var(--mu);white-space:nowrap;letter-spacing:.5px;direction:ltr">Ctrl+N: منتج &nbsp;·&nbsp; Ctrl+O: طلبيات &nbsp;·&nbsp; Ctrl+A: تحليلات &nbsp;·&nbsp; Ctrl+F: بحث &nbsp;·&nbsp; Ctrl+S: حفظ &nbsp;·&nbsp; Ctrl+P: طباعة &nbsp;·&nbsp; Ctrl+D: ولايات &nbsp;·&nbsp; F11: ملء الشاشة &nbsp;·&nbsp; 1–9: تبويبات &nbsp;·&nbsp; Esc: إغلاق</div>
<!-- VOID GLITCH ENTITY -->
<div id="void-glitch"><canvas id="vg-canvas" width="120" height="80"></canvas></div>
<div id="robot-doll">⬚</div>

<script>
/* ══════════════════════════════════════════════════════════════
   WOW STORE — Client JS v11.0 — Stable Production Build
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
  /* ── FAST TAP: prevents 300ms ghost-click on touch devices ── */
  function _fastTap(el,fn){
    if(!el)return;
    var _tapped=false;
    el.addEventListener("touchend",function(e){
      e.preventDefault();
      if(_tapped)return;
      _tapped=true;
      fn(e);
      setTimeout(function(){_tapped=false;},350);
    },{passive:false});
    el.addEventListener("click",function(e){
      if(_tapped){e.stopPropagation();return;}
      fn(e);
    });
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
  /* -- م37: margin preview -- */
  function _updateMarginPreview(){
    var pr=parseFloat((document.getElementById("p-price")||{}).value)||0;
    var dc=parseFloat((document.getElementById("p-disc")||{}).value)||0;
    var cp=parseFloat((document.getElementById("p-cost")||{}).value)||0;
    var mp=document.getElementById("p-margin-preview");
    if(!mp)return;
    if(!pr||!cp){mp.value="";return;}
    var sell=dc>0?Math.round(pr*(1-dc/100)):pr;
    var margin=sell-cp;
    var pct=Math.round(margin/sell*100);
    mp.value=margin.toLocaleString()+" دج ("+pct+"%)";
    mp.style.color=margin>=0?"rgba(74,222,128,.8)":"rgba(239,68,68,.8)";
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
  /* ── م27: فحص تنبيهات نفاد المخزون (storefront + admin badge) ── */
  function _checkAlertQty(){
    var alerts=_prods.filter(function(p){
      return p.alertQty&&p.alertQty>0&&p.quantity!==null&&p.quantity!==undefined&&p.quantity<=p.alertQty;
    });
    if(!alerts.length)return;
    /* عرض badge في header */
    var hdr=document.querySelector(".site-hdr")||document.getElementById("store-name-hdr");
    var badgeId="wow-alert-badge";
    if(!document.getElementById(badgeId)&&hdr){
      var badge=document.createElement("span");
      badge.id=badgeId;
      badge.style.cssText="background:rgba(239,68,68,.18);border:1px solid rgba(239,68,68,.35);color:rgba(239,68,68,.9);font-size:9px;padding:2px 7px;border-radius:10px;margin-right:6px;vertical-align:middle;cursor:pointer";
      badge.title=alerts.map(function(p){return p.name+" ("+p.quantity+" متبقي)";}).join("\\n");
      badge.textContent=alerts.length+" منتج على وشك النفاد";
      hdr.parentNode&&hdr.parentNode.insertBefore(badge,hdr.nextSibling);
    }
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
        var badgesHtml=(p.salesCount>0?"<div class='sales-counter'>"+p.salesCount+" مباع</div>":"")
          +(p.flashDisc?"<div class='flash-badge'>Flash "+_esc(p.flashDisc)+"%</div>":"");
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

  /* ── PRODUCTS LOAD ── */
  function _loadProds(){
    _showSkeletons();
    _api("/api/products").then(function(r){return r.json();}).then(function(data){
      _setApiSt(true);_prods=Array.isArray(data)&&data.length?data:[];
      _renderGrid();
      _checkAlertQty(); /* م27 */
    }).catch(function(){_setApiSt(false);_prods=[];_renderGrid();});
  }

  /* ── PRODUCT DETAIL ── */
  function _openProd(id){
    try{
      var p=_prods.find(function(x){return String(x.id)===String(id);});if(!p)return;
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
  function _openProdMod(prod){
    if(prod&&typeof prod==="object")_openProd(prod.id);
    else _openProd(prod);
  }

  /* ── SIZE ── */
  function _openSizeMod(id){
    try{
      var p=_prods.find(function(x){return x.id===id;});if(!p)return;
      _pendProd=p;_selSz=null;
      document.querySelectorAll(".sz-btn").forEach(function(b){b.classList.remove("on");});
      var mw=document.getElementById("mw");var mh=document.getElementById("mh");var mg=document.getElementById("mg");
      if(mw)mw.value="";if(mh)mh.value="";if(mg)mg.value="";
      var spn=document.getElementById("size-prod-name");if(spn)spn.textContent=p.name+" — ";
      /* م26: تحديث خيارات المقاس مع قفل المنفد */
      var sc=document.getElementById("size-choices");
      if(sc){
        var variantQty=p.variantQty||{};
        sc.innerHTML=(p.sizes||[]).map(function(sz){
          var vq=variantQty[sz];
          var oos=(vq!==undefined&&vq!==null&&vq<=0);
          return "<button class='sz-btn"+(oos?" sz-oos":"")+"'"
            +" data-sz='"+_esc(sz)+"'"
            +(oos?" disabled title='نفد المخزون'":" title='المتوفر: "+(vq!==undefined?vq:"∞")+"'")
            +">"+_esc(sz)
            +(oos?"<small style='display:block;font-size:8px;opacity:.5'>نفد</small>":"")
            +"</button>";
        }).join("");
        sc.querySelectorAll(".sz-btn:not(.sz-oos)").forEach(function(b){
          b.addEventListener("click",function(){_pickSz(b.getAttribute("data-sz"),b);});
        });
      }
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
      if(!("serviceWorker" in navigator)){_toast("المتصفح لا يدعم Service Worker");return;}
      navigator.serviceWorker.register("/sw.js").then(function(reg){
        if(reg.showNotification)reg.showNotification("WOW Store",{body:"الإشعارات المحلية مفعلة"});
        var bn=document.getElementById("push-banner");if(bn)bn.style.display="none";
        _toast("تم تفعيل الإشعارات المحلية");
      }).catch(function(){_toast("خطا في تفعيل Service Worker");});
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
        var shipCost=0;
        try{var _sc=parseFloat(localStorage.getItem("wow_ship_cost")||"0");shipCost=_sc||0;}catch(e){}
        var confOrders=_ordersCache.filter(function(o){return o.confirmed;});
        var grossRev=confOrders.reduce(function(a,o){return a+(o.total||0);},0);
        var totalCost=confOrders.reduce(function(a,o){
          return a+(o.items||[]).reduce(function(b,it){return b+(it.costPrice||0)*it.qty;},0)+shipCost;
        },0);
        var netProfit=grossRev-totalCost;
        var avgMargin=grossRev>0?Math.round(netProfit/grossRev*100):0;
        var convRate=d.uniqueVisitors>0?((d.confirmedOrders||0)/d.uniqueVisitors*100).toFixed(1):"0.0";
        var avgCart=confOrders.length>0?Math.round(grossRev/confOrders.length):0;
        kpiRow.innerHTML=mkKPI("إيرادات الأسبوع",_fmt(d.revThisWeek||0)+" دج","مقارنة بالأسبوع الماضي",wTrend)
          +mkKPI("إيرادات الشهر",_fmt(d.revThisMonth||0)+" دج","مقارنة بالشهر الماضي",mTrend)
          +mkKPI("طلبيات الأسبوع",(d.ordersThisWeek||0)+" طلبية","vs الأسبوع الماضي",oTrend)
          +mkKPI("صافي الربح",_fmt(netProfit)+" دج","بعد خصم التكلفة + الشحن",avgMargin>0?avgMargin:0)
          +mkKPI("هامش الربح",avgMargin+"%","صافي / إيراد مؤكد",0)
          +mkKPI("معدل التحويل",convRate+"%","زوار → طلبية",0)
          +mkKPI("متوسط السلة",_fmt(avgCart)+" دج","للطلبيات المؤكدة",0);
      }
      // -- Stat Cards --
      var sc=document.getElementById("stat-cards");
      if(sc){sc.innerHTML=[
        {l:"\u0625\u062c\u0645\u0627\u0644\u064a \u0627\u0644\u0632\u064a\u0627\u0631\u0627\u062a",v:d.totalVisits},
        {l:"\u0632\u0648\u0627\u0631 \u0641\u0631\u064a\u062f\u0648\u0646",v:d.uniqueVisitors},
        {l:"\u0625\u062c\u0645\u0627\u0644\u064a \u0627\u0644\u0637\u0644\u0628\u064a\u0627\u062a",v:d.totalOrders},
        {l:"\u0637\u0644\u0628\u064a\u0627\u062a \u0645\u0624\u0643\u062f\u0629",v:d.confirmedOrders},
        {l:"\u0627\u0644\u0625\u064a\u0631\u0627\u062f \u0627\u0644\u0643\u0644\u064a",v:_fmt(d.revenue)+"\u062f\u062c"},
        {l:"\u0635\u0627\u0641\u064a \u0627\u0644\u0631\u0628\u062d",v:_fmt(netProfit)+"\u062f\u062c"},
        {l:"\u0647\u0627\u0645\u0634 \u0627\u0644\u0631\u0628\u062d",v:avgMargin+"%"},
        {l:"\u0627\u0644\u0645\u0646\u062a\u062c\u0627\u062a",v:d.productCount},
        {l:"\u0645\u0631\u062a\u062c\u0639\u0629",v:(d.returnedCount||0)}
      ].map(function(x){return "<div class='sk'><div class='sk-l'>"+x.l+"</div><div class='sk-v'>"+x.v+"</div></div>";}).join("");}

      // -- Sales Chart SVG (m15) --
      (function(){
        var sc2=document.getElementById("sales-chart");
        var sct=document.getElementById("sales-chart-total");
        if(!sc2)return;
        // build daily map from orders cache
        var dayMap={};
        var now=Date.now();
        var day14=14*24*3600*1000;
        _ordersCache.forEach(function(o){
          if(!o.date)return;
          var oms=new Date(o.date).getTime();
          if(now-oms>day14)return;
          var dk=new Date(o.date).toLocaleDateString("fr-DZ",{day:"2-digit",month:"2-digit"});
          if(!dayMap[dk])dayMap[dk]={rev:0,cnt:0};
          dayMap[dk].cnt++;
          if(o.confirmed)dayMap[dk].rev+=(o.total||0);
        });
        // fill last 14 days
        var days=[];
        for(var i=13;i>=0;i--){
          var d2=new Date(now-i*24*3600*1000);
          var dk=d2.toLocaleDateString("fr-DZ",{day:"2-digit",month:"2-digit"});
          days.push({lbl:dk,rev:(dayMap[dk]||{}).rev||0,cnt:(dayMap[dk]||{}).cnt||0});
        }
        var maxRev=Math.max.apply(null,days.map(function(x){return x.rev;}))||1;
        var totalRevPeriod=days.reduce(function(a,x){return a+x.rev;},0);
        if(sct)sct.textContent=_fmt(totalRevPeriod);
        var W=Math.max(300,days.length*38),H=120,PB=28,PT=10,PR=10,PL=40;
        var IW=W-PL-PR,IH=H-PT-PB;
        var pts=days.map(function(x,i){
          var cx=PL+IW/(days.length-1||1)*i;
          var cy=PT+IH-(x.rev/maxRev)*IH;
          return {cx:Math.round(cx),cy:Math.round(cy),rev:x.rev,cnt:x.cnt,lbl:x.lbl};
        });
        // area path
        var areaD="M"+PL+","+(PT+IH);
        pts.forEach(function(p){areaD+=" L"+p.cx+","+p.cy;});
        areaD+=" L"+(PL+IW)+","+(PT+IH)+" Z";
        // line path
        var lineD=pts.map(function(p,i){return (i===0?"M":"L")+p.cx+","+p.cy;}).join(" ");
        // y axis labels
        var yLabels="";
        for(var yi=0;yi<=4;yi++){
          var yv=Math.round(maxRev*yi/4);
          var yp=PT+IH-IH*yi/4;
          yLabels+="<text x='"+(PL-4)+"' y='"+(yp+4)+"' text-anchor='end' font-size='8' fill='rgba(255,255,255,.25)'>"+
            (yv>=1000?Math.round(yv/1000)+"k":yv)+"</text>"+
            "<line x1='"+PL+"' y1='"+yp+"' x2='"+(PL+IW)+"' y2='"+yp+"' stroke='rgba(255,255,255,.04)' stroke-width='1'/>";
        }
        // x labels (every 2nd)
        var xLabels="";
        pts.forEach(function(p,i){
          if(i%2===0)xLabels+="<text x='"+p.cx+"' y='"+(H-8)+"' text-anchor='middle' font-size='8' fill='rgba(255,255,255,.3)'>"+p.lbl+"</text>";
        });
        // dots + tooltips
        var dots="";
        pts.forEach(function(p){
          dots+="<circle cx='"+p.cx+"' cy='"+p.cy+"' r='3.5' fill='#a855f7' stroke='rgba(10,0,30,.8)' stroke-width='1.5'>"+
            "<title>"+p.lbl+" — "+p.cnt+" \u0637\u0644\u0628\u064a\u0629 — "+_fmt(p.rev)+"</title></circle>";
        });
        var svg="<svg xmlns='http://www.w3.org/2000/svg' width='"+W+"' height='"+H+"' style='min-width:"+W+"px'>"+
          "<defs><linearGradient id='sg' x1='0' y1='0' x2='0' y2='1'>"+
          "<stop offset='0%' stop-color='rgba(168,85,247,.35)'/>"+
          "<stop offset='100%' stop-color='rgba(168,85,247,.03)'/></linearGradient></defs>"+
          yLabels+xLabels+
          "<path d='"+areaD+"' fill='url(#sg)'/>"+
          "<path d='"+lineD+"' fill='none' stroke='rgba(192,132,252,.8)' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"+
          dots+"</svg>";
        sc2.innerHTML="<div style='overflow-x:auto'>"+svg+"</div>";
      })();

      // -- Brand Chart --
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
      // -- Device Chart --
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
      // -- Hour Chart --
      var hc=document.getElementById("hr-chart");
      if(hc&&d.hourMap){
        var maxH=Math.max.apply(null,Object.values(d.hourMap))||1;
        var bars="";
        for(var h=0;h<24;h++){
          var v=d.hourMap[h]||0;var pct=Math.round(v/maxH*100)||1;
          bars+="<div title='"+h+":00 - "+v+" \u0632\u064a\u0627\u0631\u0629' style='display:inline-flex;flex-direction:column;align-items:center;gap:2px;width:3.8%'>"
            +"<div style='height:"+(pct*0.5)+"px;background:rgba(168,85,247,.5);border-radius:2px 2px 0 0;width:100%;min-height:2px'></div>"
            +"<div style='font-size:7px;color:var(--mu)'>"+h+"</div></div>";
        }
        hc.innerHTML="<div style='display:flex;align-items:flex-end;height:50px;overflow:hidden'>"+bars+"</div>";
      }
      // -- Wilaya Bar Chart (m15) --
      var wc=document.getElementById("wilaya-chart");
      if(wc){
        // build wilaya map from orders cache
        var wmap={};
        _ordersCache.filter(function(o){return o.confirmed;}).forEach(function(o){
          var w=o.wilaya||"\u063a\u064a\u0631 \u0645\u062d\u062f\u062f";
          if(!wmap[w])wmap[w]={cnt:0,rev:0};
          wmap[w].cnt++;wmap[w].rev+=(o.total||0);
        });
        var sortedW=Object.entries(wmap).sort(function(a,b){return b[1].cnt-a[1].cnt;}).slice(0,12);
        if(sortedW.length){
          var maxW=sortedW[0][1].cnt||1;
          wc.innerHTML="<div style='margin-bottom:4px;font-size:9px;color:var(--mu)'>\u0637\u0644\u0628\u064a\u0627\u062a \u0645\u0624\u0643\u062f\u0629 \u062d\u0633\u0628 \u0627\u0644\u0648\u0644\u0627\u064a\u0629</div>"+
            sortedW.map(function(e){
              var pct=Math.round(e[1].cnt/maxW*100);
              return "<div style='display:flex;align-items:center;gap:7px;margin-bottom:5px'>"
                +"<div style='width:90px;font-size:10px;color:var(--dim);text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>"+_esc(e[0])+"</div>"
                +"<div style='flex:1;background:rgba(255,255,255,.05);border-radius:3px;height:10px;position:relative'>"
                +"<div style='width:"+pct+"%;height:100%;background:linear-gradient(90deg,rgba(168,85,247,.65),rgba(109,40,217,.4));border-radius:3px;transition:width .4s'></div></div>"
                +"<div style='font-size:9px;color:var(--mu);width:40px;text-align:left'>"+e[1].cnt+" \u0637</div></div>";
            }).join("")+
            (d.bestProd?"<div style='margin-top:8px;font-size:10px;color:var(--dim)'>\u0623\u0643\u062b\u0631 \u0645\u0646\u062a\u062c \u0645\u0628\u064a\u0639\u0627: <span style='color:rgba(192,132,252,.9)'>"+_esc(d.bestProd.name)+"</span> ("+d.bestProd.qty+" \u0642\u0637\u0639\u0629)</div>":"");
        } else {
          wc.innerHTML="<div style='font-size:11px;color:var(--mu)'>\u0644\u0627 \u0628\u064a\u0627\u0646\u0627\u062a \u0628\u0639\u062f</div>";
        }
      }
      // -- Algeria Map SVG (m16) --
      (function(){
        var mc=document.getElementById("algeria-map-c");
        if(!mc)return;
        // build wilaya order counts from cache
        var wCounts={};
        _ordersCache.filter(function(o){return o.confirmed;}).forEach(function(o){
          var w=o.wilaya||"";
          if(w)wCounts[w]=(wCounts[w]||0)+1;
        });
        var maxC=Math.max.apply(null,Object.values(wCounts).concat([1]));
        // Algeria 58 wilayas simplified coordinate map (cx, cy for label positions)
        // Arranged roughly geographically on a 520x380 canvas
        var WILAYAS=[
          {n:"\u0627\u0644\u062c\u0632\u0627\u0626\u0631",x:230,y:90},
          {n:"\u0648\u0647\u0631\u0627\u0646",x:140,y:85},
          {n:"\u0642\u0633\u0646\u0637\u064a\u0646\u0629",x:280,y:80},
          {n:"\u0639\u0646\u0627\u0628\u0629",x:310,y:68},
          {n:"\u0628\u062c\u0627\u064a\u0629",x:260,y:72},
          {n:"\u062a\u064a\u0632\u064a \u0648\u0632\u0648",x:245,y:78},
          {n:"\u0633\u0637\u064a\u0641",x:278,y:85},
          {n:"\u0628\u0627\u062a\u0646\u0629",x:290,y:90},
          {n:"\u0627\u0644\u0628\u0644\u064a\u062f\u0629",x:222,y:92},
          {n:"\u0628\u0648\u0645\u0631\u062f\u0627\u0633",x:232,y:83},
          {n:"\u0645\u0633\u062a\u063a\u0627\u0646\u0645",x:150,y:80},
          {n:"\u0633\u064a\u062f\u064a \u0628\u0644\u0639\u0628\u0627\u0633",x:130,y:90},
          {n:"\u062a\u0644\u0645\u0633\u0627\u0646",x:110,y:95},
          {n:"\u0627\u0644\u0634\u0644\u0641",x:175,y:95},
          {n:"\u062a\u064a\u0627\u0631\u062a",x:165,y:108},
          {n:"\u0645\u0639\u0633\u0643\u0631",x:155,y:105},
          {n:"\u063a\u0644\u064a\u0632\u0627\u0646",x:162,y:92},
          {n:"\u062a\u064a\u0628\u0627\u0632\u0629",x:215,y:88},
          {n:"\u0639\u064a\u0646 \u062a\u0645\u0648\u0634\u0646\u062a",x:138,y:82},
          {n:"\u0628\u0631\u062c \u0628\u0648\u0639\u0631\u064a\u0631\u064a\u062c",x:258,y:88},
          {n:"\u0627\u0644\u0628\u0648\u064a\u0631\u0629",x:242,y:88},
          {n:"\u0627\u0644\u0645\u062f\u064a\u0629",x:220,y:100},
          {n:"\u062a\u064a\u0633\u0645\u0633\u064a\u0644\u062a",x:185,y:100},
          {n:"\u0639\u064a\u0646 \u0627\u0644\u062f\u0641\u0644\u0649",x:210,y:105},
          {n:"\u062c\u064a\u062c\u0644",x:275,y:73},
          {n:"\u0633\u0643\u064a\u0643\u062f\u0629",x:298,y:73},
          {n:"\u0642\u0627\u0644\u0645\u0629",x:300,y:78},
          {n:"\u0633\u0648\u0642 \u0627\u0647\u0631\u0627\u0633",x:305,y:83},
          {n:"\u0627\u0644\u0637\u0627\u0631\u0641",x:318,y:72},
          {n:"\u062e\u0646\u0634\u0644\u0629",x:295,y:95},
          {n:"\u0645\u064a\u0644\u0629",x:285,y:78},
          {n:"\u0623\u0645 \u0627\u0644\u0628\u0648\u0627\u0642\u064a",x:295,y:85},
          {n:"\u062a\u0628\u0633\u0629",x:308,y:88},
          {n:"\u0633\u0639\u064a\u062f\u0629",x:140,y:100},
          {n:"\u0627\u0644\u0646\u0639\u0627\u0645\u0629",x:120,y:110},
          {n:"\u0628\u064a\u0634\u0627\u0631",x:115,y:125},
          {n:"\u0627\u0644\u0628\u064a\u0636",x:130,y:120},
          {n:"\u0627\u0644\u0627\u063a\u0648\u0627\u0637",x:185,y:130},
          {n:"\u0627\u0644\u062c\u0644\u0641\u0629",x:205,y:125},
          {n:"\u063a\u0631\u062f\u0627\u064a\u0629",x:195,y:155},
          {n:"\u0648\u0631\u0642\u0644\u0629",x:230,y:170},
          {n:"\u062a\u0642\u0631\u062a",x:250,y:175},
          {n:"\u0627\u0644\u0648\u0627\u062f\u064a",x:265,y:160},
          {n:"\u0648\u0627\u062f\u064a \u0633\u0648\u0641",x:270,y:155},
          {n:"\u0627\u0644\u0645\u063a\u064a\u0631",x:268,y:165},
          {n:"\u0628\u0633\u0643\u0631\u0629",x:255,y:140},
          {n:"\u062e\u0646\u0634\u0644\u0629",x:295,y:110},
          {n:"\u0637\u0648\u0644\u0642\u0629",x:240,y:148},
          {n:"\u0627\u0644\u0645\u0633\u064a\u0644\u0629",x:230,y:130},
          {n:"\u062a\u0646\u062f\u0648\u0641",x:80,y:145},
          {n:"\u0627\u062f\u0631\u0627\u0631",x:105,y:215},
          {n:"\u062a\u064a\u0645\u064a\u0645\u0648\u0646",x:130,y:195},
          {n:"\u0628\u0646\u064a \u0639\u0628\u0627\u0633",x:115,y:160},
          {n:"\u0639\u064a\u0646 \u0635\u0627\u0644\u062d",x:190,y:230},
          {n:"\u062a\u0645\u0646\u0631\u0627\u0633\u062a",x:230,y:260},
          {n:"\u064a\u0644\u064a\u0632\u064a",x:310,y:210},
          {n:"\u0627\u0644\u064a\u0632\u064a",x:290,y:215},
          {n:"\u062c\u0627\u0646\u062a",x:270,y:290},
          {n:"\u0639\u064a\u0646 \u0642\u0632\u0627\u0645",x:80,y:300}
        ];
        var W=360,H=320;
        var circles="";var labels="";var legend="";
        WILAYAS.forEach(function(w){
          var cnt=wCounts[w.n]||0;
          var ratio=cnt/maxC;
          var r=cnt>0?5+Math.round(ratio*16):3; /* حجم أكبر للوضوح */
          var alpha=cnt>0?(0.3+ratio*0.7).toFixed(2):"0.12";
          /* م16: تدرج حراري HSL — أزرق (مبيعات منخفضة) إلى أحمر (مبيعات عالية) */
          var hue=cnt>0?Math.round(240-ratio*240):240; /* 240=أزرق 0=أحمر */
          var sat=cnt>0?70:20;
          var lit=cnt>0?Math.round(55-ratio*20):75;
          var alphaF=cnt>0?(0.25+ratio*0.65).toFixed(2):"0.07";
          var fillColor="hsla("+hue+","+sat+"%,"+lit+"%,"+alphaF+")";
          var strokeColor=cnt>0?"rgba(255,255,255,.35)":"rgba(168,85,247,.12)";
          circles+="<circle cx='"+w.x+"' cy='"+w.y+"' r='"+r+"' fill='"+fillColor+"' stroke='"+strokeColor+"' stroke-width='1'>"
            +"<title>"+w.n+" — "+cnt+" \u0637\u0644\u0628\u064a\u0629</title></circle>";
          if(cnt>0){
            labels+="<text x='"+(w.x+r+2)+"' y='"+(w.y+4)+"' font-size='7' fill='rgba(192,132,252,.75)'>"+_esc(w.n)+"</text>";
          }
        });
        // legend
        legend="<g transform='translate(10,295)'>"
          +"<text x='0' y='0' font-size='8' fill='rgba(255,255,255,.3)'>\u0627\u0644\u062d\u062c\u0645 \u064a\u0639\u0643\u0633 \u0639\u062f\u062f \u0627\u0644\u0637\u0644\u0628\u064a\u0627\u062a</text>"
          +"<circle cx='5' cy='12' r='3' fill='rgba(168,85,247,.15)' stroke='rgba(168,85,247,.3)' stroke-width='1'/>"
          +"<text x='12' y='16' font-size='8' fill='rgba(255,255,255,.25)'>\u0644\u0627 \u0637\u0644\u0628\u064a\u0627\u062a</text>"
          +"<circle cx='65' cy='12' r='8' fill='rgba(239,108,148,.7)' stroke='rgba(192,132,252,.6)' stroke-width='1'/>"
          +"<text x='77' y='16' font-size='8' fill='rgba(255,255,255,.25)'>\u0623\u0643\u062b\u0631 \u0637\u0644\u0628\u064a\u0627\u062a</text></g>";
        var svg="<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 "+W+" "+H+"' width='"+W+"' height='"+H+"' style='min-width:"+W+"px'>"
          +"<rect width='"+W+"' height='"+H+"' fill='rgba(168,85,247,.02)' rx='8'/>"
          +circles+labels+legend+"</svg>";
        mc.innerHTML=svg;
        if(maxC>1){
          mc.innerHTML+=("<div style='font-size:9px;color:var(--mu);margin-top:4px;text-align:center'>"
            +"\u0623\u0643\u062b\u0631 \u0648\u0644\u0627\u064a\u0629: "
            +(Object.entries(wCounts).sort(function(a,b){return b[1]-a[1];})[0]||["",""])[0]
            +" (\u0637\u0644\u0628\u064a\u0629 "
            +(Object.entries(wCounts).sort(function(a,b){return b[1]-a[1];})[0]||["",0])[1]
            +")</div>");
        }
      })()
      // ── API Status ───────────────────────────────────────────────
      var ad=document.getElementById("api-d"),al=document.getElementById("api-l");
      if(ad){ad.className="api-d";ad.style.background="#22c55e";}
      if(al)al.textContent="Connected";
    }).catch(function(){
      var ad=document.getElementById("api-d"),al=document.getElementById("api-l");
      if(ad){ad.style.background="#ef4444";}if(al)al.textContent="Error";
    });
  }

  function _loadKvStats(){
    var c=document.getElementById("kv-stats-c");if(c)c.innerHTML="<span class='spin'></span> Loading...";
    _api("/api/kv-stats").then(function(r){return r.json();}).then(function(d){
      if(d.error){if(c)c.textContent=d.error;return;}
      var pct=Math.round((d.pctUsed||0)*100)/100;
      var keys=(d.keyDetails||[]).map(function(k){return "<div style='display:flex;justify-content:space-between;border-top:1px solid var(--b1);padding:5px 0'><span>"+_esc(k.key)+"</span><span>"+_fmt(Math.round((k.bytes||0)/1024))+" KB</span></div>";}).join("");
      if(c)c.innerHTML="<div style='margin-bottom:8px'>"+_fmt(Math.round(d.usedMB||0))+" MB / "+_fmt(Math.round(d.totalMB||1024))+" MB — "+pct+"%</div>"
        +"<div style='height:7px;background:rgba(255,255,255,.06);border-radius:999px;overflow:hidden;margin-bottom:8px'><div style='height:100%;width:"+Math.min(100,pct)+"%;background:linear-gradient(90deg,#22c55e,#a855f7)'></div></div>"+keys;
    }).catch(function(){if(c)c.textContent="خطأ في تحميل الإحصائيات";});
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
    var esz=document.getElementById("s-sizes");if(esz)esz.value=(p.sizes||[]).join(",");
    var eco=document.getElementById("s-colors");if(eco)eco.value=(p.colors||[]).join(",");
    var eal=document.getElementById("s-alertqty");if(eal)eal.value=p.alertQty||"";
    var esa=document.getElementById("s-showat");if(esa&&p.showAt)esa.value=p.showAt.slice(0,16);
    var ecp=document.getElementById("p-cost");if(ecp)ecp.value=p.costPrice||"";
    _updateMarginPreview();
    var fh=document.getElementById("form-head");if(fh)fh.textContent="Edit Product";
    _aTab("addprod",null);
  }
  /* -- CONFIRM-MOD STATE m3 (Phase 2: pointer-unified, no mousedown dependency) -- */
  var _confirmHoldRaf=null,_confirmHoldActive=false,_confirmHoldTimer=null;

  function _showConfirmMod(opts){
    var mod=document.getElementById("confirm-mod");
    var info=document.getElementById("confirm-mod-info");
    var inp=document.getElementById("confirm-mod-inp");
    var archBtn=document.getElementById("confirm-mod-archive-btn");
    var cancelBtn=document.getElementById("confirm-mod-cancel");
    var delBtn=document.getElementById("confirm-mod-del-btn");
    var bar=document.getElementById("confirm-hold-bar");
    if(!mod)return;

    /* ── reset state ── */
    if(info)info.textContent=opts.info||"";
    if(inp)inp.value="";
    if(delBtn){delBtn.classList.remove("ready");delBtn.textContent="اضغط مطولا للحذف";}
    if(bar){bar.style.width="0";bar.style.transition="none";}
    _confirmHoldActive=false;
    if(_confirmHoldRaf){cancelAnimationFrame(_confirmHoldRaf);_confirmHoldRaf=null;}
    if(_confirmHoldTimer){clearTimeout(_confirmHoldTimer);_confirmHoldTimer=null;}

    /* ── helpers ── */
    function _isTyped(){return inp&&inp.value.trim()==="حذف";}
    function _cleanup(){
      if(_confirmHoldRaf){cancelAnimationFrame(_confirmHoldRaf);_confirmHoldRaf=null;}
      if(_confirmHoldTimer){clearTimeout(_confirmHoldTimer);_confirmHoldTimer=null;}
      _confirmHoldActive=false;
      mod.style.display="none";
      /* remove pointer listeners to avoid accumulation */
      if(delBtn){
        delBtn.removeEventListener("pointerdown",_onPDown);
        delBtn.removeEventListener("pointerup",_onPUp);
        delBtn.removeEventListener("pointercancel",_stopHold);
        delBtn.removeEventListener("pointerleave",_stopHold);
      }
      if(archBtn)archBtn.onclick=null;
      if(cancelBtn)cancelBtn.onclick=null;
      mod.onclick=null;
    }
    function _execDelete(){_cleanup();if(typeof opts.onDelete==="function")opts.onDelete();}

    /* ── archive / cancel / backdrop ── */
    if(archBtn){
      archBtn.onclick=function(){
        _cleanup();
        if(typeof opts.onArchive==="function")opts.onArchive();
      };
    }
    if(cancelBtn){cancelBtn.onclick=_cleanup;}
    mod.onclick=function(e){if(e.target===mod)_cleanup();};

    /* ── typed input watcher ── */
    if(inp){
      inp.oninput=function(){
        var typed=_isTyped();
        if(delBtn){
          if(typed){
            delBtn.classList.add("ready");
            delBtn.textContent="حذف نهائي";
          } else if(!_confirmHoldActive){
            delBtn.classList.remove("ready");
            delBtn.textContent="اضغط مطولا للحذف";
          }
        }
        if(bar&&!_confirmHoldActive)bar.style.width=typed?"100%":"0";
      };
    }

    /* ── hold-bar RAF animation ── */
    function _startHold(){
      if(_confirmHoldActive)return;
      _confirmHoldActive=true;
      if(bar){bar.style.transition="none";bar.style.width="0";}
      var start=performance.now(),dur=2000;
      function tick(now){
        var pct=Math.min(100,Math.round((now-start)/dur*100));
        if(bar)bar.style.width=pct+"%";
        if(pct>=100){
          _confirmHoldActive=false;
          _execDelete();
        } else {
          _confirmHoldRaf=requestAnimationFrame(tick);
        }
      }
      _confirmHoldRaf=requestAnimationFrame(tick);
    }
    function _stopHold(){
      if(_confirmHoldRaf){cancelAnimationFrame(_confirmHoldRaf);_confirmHoldRaf=null;}
      if(_confirmHoldTimer){clearTimeout(_confirmHoldTimer);_confirmHoldTimer=null;}
      _confirmHoldActive=false;
      if(!_isTyped()){
        if(bar){bar.style.transition="width 0.15s ease";bar.style.width="0";}
        if(delBtn){
          delBtn.classList.remove("ready");
          delBtn.textContent="اضغط مطولا للحذف";
        }
      }
    }

    /* ── Pointer Events (covers mouse + touch + stylus uniformly) ── */
    function _onPDown(e){
      /* only primary pointer (left-click or first finger) */
      if(!e.isPrimary)return;
      e.preventDefault();
      /* if "حذف" already typed, single tap is enough */
      if(_isTyped()){_execDelete();return;}
      delBtn.setPointerCapture(e.pointerId);
      _startHold();
    }
    function _onPUp(e){
      if(!e.isPrimary)return;
      e.preventDefault();
      if(_isTyped()){_execDelete();}
      else{_stopHold();}
    }

    if(delBtn){
      /* touch-action none so pointerdown fires immediately without 300ms */
      delBtn.style.touchAction="none";
      delBtn.addEventListener("pointerdown",_onPDown,{passive:false});
      delBtn.addEventListener("pointerup",_onPUp,{passive:false});
      delBtn.addEventListener("pointercancel",_stopHold);
      delBtn.addEventListener("pointerleave",_stopHold);
    }

    mod.style.display="flex";
    /* delay focus to avoid virtual keyboard shift on mobile */
    _confirmHoldTimer=setTimeout(function(){
      _confirmHoldTimer=null;
      if(inp)inp.focus();
    },120);
  }

  function _delProd(id){
    _api("/api/products").then(function(r){return r.json();}).then(function(data){
      var p=(data||[]).find(function(x){return x.id===id||x.id===+id;});
      _showConfirmMod({
        info:(p?p.name:"المنتج")+"\\nالحذف النهائي لا يمكن التراجع عنه.",
        onArchive:function(){_api("/api/products?id="+id+"&archive=1",{method:"DELETE"}).then(function(){_loadAdmProds();_toast("تمت الارشفة");}).catch(function(){_toast("خطا");});},
        onDelete:function(){_api("/api/products?id="+id,{method:"DELETE"}).then(function(){_loadAdmProds();_toast("تم الحذف النهائي");}).catch(function(){_toast("خطا");});}
      });
    }).catch(function(){
      _showConfirmMod({
        info:"الحذف النهائي لا يمكن التراجع عنه.",
        onArchive:function(){_api("/api/products?id="+id+"&archive=1",{method:"DELETE"}).then(function(){_loadAdmProds();_toast("تمت الارشفة");}).catch(function(){_toast("خطا");});},
        onDelete:function(){_api("/api/products?id="+id,{method:"DELETE"}).then(function(){_loadAdmProds();_toast("تم الحذف النهائي");}).catch(function(){_toast("خطا");});}
      });
    });
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
    var extras=_b3ExtraFields();
    var costPriceEl=document.getElementById("p-cost");
    var costPrice=costPriceEl&&costPriceEl.value!=""?Math.max(0,parseFloat(costPriceEl.value)||0):0;
    var body={name:name,price:+price,discount:disc,cat:cat,desc:desc,quantity:qty,images:_prodImgs.map(function(x){return x.url;}),sizes:extras.sizes||[],colors:extras.colors||[],alertQty:extras.alertQty||0,showAt:extras.showAt||null,costPrice:costPrice}
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
      var ecp=document.getElementById("p-cost");if(ecp)ecp.value="";
      var emp=document.getElementById("p-margin-preview");if(emp)emp.value="";
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

  /* -- م8 Phase 3: bind instant filters (once) — status, conf, rep, q, wilaya, phone -- */
  var _filtersBound=false;
  function _bindInstantFilters(){
    if(_filtersBound)return;_filtersBound=true;
    /* selects: fire on change */
    ["ord-f-status","ord-f-conf","ord-f-rep"].forEach(function(id){
      var el=document.getElementById(id);
      if(el)el.addEventListener("change",function(){_filterOrders();});
    });
    /* text inputs: debounce 220ms */
    ["ord-f-q","ord-f-wilaya","ord-f-phone"].forEach(function(id){
      var el=document.getElementById(id);
      if(!el)return;
      el.addEventListener("input",function(){
        clearTimeout(_filterDebounce);
        _filterDebounce=setTimeout(function(){_filterOrders();},220);
      });
      el.addEventListener("keydown",function(e){
        if(e.key==="Escape"){el.value="";_filterOrders();}
      });
    });
    /* clear-all button */
    var clr=document.getElementById("ord-f-clear-btn");
    if(clr){
      clr.addEventListener("click",function(){
        ["ord-f-status","ord-f-conf","ord-f-rep"].forEach(function(id){
          var el=document.getElementById(id);if(el)el.value="";
        });
        ["ord-f-q","ord-f-wilaya","ord-f-phone"].forEach(function(id){
          var el=document.getElementById(id);if(el)el.value="";
        });
        try{window.history.replaceState(null,"",window.location.pathname);}catch(e){}
        _renderOrders(_ordersCache);
        var rf=document.getElementById("ord-refresh");
        if(rf)rf.textContent="("+_ordersCache.length+" — "+new Date().toLocaleTimeString("ar-DZ")+")";
      });
    }
  }

  /* -- م9 Phase 4: online sync -- flush pending note drafts on reconnect -- */
  (function(){
    function _flushPendingNotes(){
      try{
        var keys=[];
        for(var i=0;i<localStorage.length;i++){
          var k=localStorage.key(i);
          if(k&&k.indexOf("wow_note_")===0)keys.push(k);
        }
        if(!keys.length)return;
        var synced=0,failed=0,total=keys.length;
        keys.forEach(function(k){
          var oid=k.replace("wow_note_","");
          var val=localStorage.getItem(k);
          if(val===null){total--;return;}
          _api("/api/orders",{method:"PATCH",body:JSON.stringify({id:oid,note:val})})
            .then(function(){
              try{localStorage.removeItem(k);}catch(e){}
              synced++;
              var ta=document.querySelector(".ord-note-inp[data-oid='"+oid+"']");
              if(ta){ta.style.borderColor="rgba(74,222,128,.35)";ta.title="تم الحفظ";}
              if(synced+failed===total&&synced>0){
                _toast("تمت مزامنة "+synced+" ملاحظة");
              }
            })
            .catch(function(){failed++;});
        });
      }catch(e){}
    }
    window.addEventListener("online",_flushPendingNotes);
    if(navigator.onLine){setTimeout(function(){_flushPendingNotes();},3000);}
  })();

  /* -- ORDERS -- */
  function _loadOrders(){
    var oc=document.getElementById("orders-c");if(oc)oc.innerHTML="<div style='color:var(--mu);font-size:12px;padding:13px'><span class='spin'></span> Loading...</div>";
    _api("/api/orders").then(function(r){return r.json();}).then(function(orders){
      _ordersCache=orders;
      _bindInstantFilters();
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
        var repBadge=o.repeated?"<span class='rep-badge'>مكررة</span>":"";
        var couponBadge=o.couponCode?"<span style='background:rgba(74,222,128,.1);border:1px solid rgba(74,222,128,.2);color:rgba(74,222,128,.8);font-size:9px;padding:2px 6px;border-radius:4px'>"+_esc(o.couponCode)+"</span>":"";
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
              +(o.auditLog&&o.auditLog.length
                ?"<details style='margin-top:4px'><summary style='font-size:9px;color:var(--mu);cursor:pointer;list-style:none'>سجل التعديلات ("+o.auditLog.length+")</summary>"
                +"<div>"+o.auditLog.map(function(en){
                  return "<div style='font-size:9px;color:var(--mu);padding:3px 6px;border-bottom:1px solid rgba(255,255,255,.03)'>"
                    +new Date(en.t).toLocaleString("ar-DZ")+" — "
                    +en.changes.map(function(ch){return ch.f+(ch.from!==undefined?": "+ch.from+" → "+ch.to:"");}).join(" · ")+"</div>";
                }).join("")+"</div></details>":"")
              +histHtml
              +"<div class='oc-ft'><span style='font-family:Georgia,serif;color:rgba(192,132,252,.9)'>"+_fmt(o.total)+"</span>"
              +"<select class='status-sel' data-oid='"+_esc(o.id)+"'>"+stOpts+"</select>"
              +(o.confirmed?"<button class='aact' data-conf='"+_esc(o.id)+"' data-val='false'>إلغاء</button>":"<button class='aact e' data-conf='"+_esc(o.id)+"' data-val='true'>تأكيد</button>")
              +"<button class='aact' data-invoice='"+_esc(o.id)+"' title='INV' style='background:rgba(99,102,241,.12);border-color:rgba(99,102,241,.3)'></button>"
              +"<button class='aact' data-shiplbl='"+_esc(o.id)+"' title='Shipping' style='background:rgba(34,197,94,.08);border-color:rgba(34,197,94,.25)'></button>"
              +"<button class='aact d' data-delord='"+_esc(o.id)+"'>X</button>"
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
      // ── م9 Note editing: debounce 1000ms + offline localStorage + online sync ──
      c.querySelectorAll(".ord-note-inp").forEach(function(ta){
        var oid=ta.getAttribute("data-oid");
        var _noteTimer=null;
        var _notePending=false;
        /* restore offline draft */
        try{
          var draft=localStorage.getItem("wow_note_"+oid);
          if(draft!==null&&draft!==ta.value){
            ta.value=draft;
            ta.style.borderColor="rgba(251,191,36,.5)";
            ta.title="مسودة غير محفوظة — ستتزامن تلقائيا";
          }
        }catch(e){}
        function _syncNote(val){
          if(!navigator.onLine){
            /* حفظ محلي فوري عند الانقطاع */
            try{localStorage.setItem("wow_note_"+oid,val);}catch(e){}
            ta.style.borderColor="rgba(251,191,36,.5)";
            ta.title="حفظ محلي — سيتزامن عند عودة الاتصال";
            _notePending=true;
            return;
          }
          _api("/api/orders",{method:"PATCH",body:JSON.stringify({id:oid,note:val})})
            .then(function(){
              try{localStorage.removeItem("wow_note_"+oid);}catch(e){}
              ta.style.borderColor="rgba(74,222,128,.35)";
              ta.title="تم الحفظ";
              _notePending=false;
            })
            .catch(function(){
              try{localStorage.setItem("wow_note_"+oid,val);}catch(e){}
              ta.style.borderColor="rgba(251,191,36,.5)";
              ta.title="حفظ محلي — سيتزامن عند عودة الاتصال";
              _notePending=true;
            });
        }
        ta.addEventListener("input",function(){
          ta.style.borderColor="rgba(168,85,247,.35)";
          ta.title="";
          /* حفظ draft في localStorage فوراً لمنع فقدان البيانات */
          try{localStorage.setItem("wow_note_"+oid,ta.value);}catch(e){}
          clearTimeout(_noteTimer);
          _noteTimer=setTimeout(function(){
            _noteTimer=null;
            _syncNote(ta.value);
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
      _restoreOrderFilters();
    }).catch(function(){var c=document.getElementById("orders-c");if(c)c.innerHTML="<div style='color:rgba(239,68,68,.7);font-size:12px;padding:13px'>خطا في التحميل</div>";});
  }
  /* -- م13 bulk print -- */
  var _selectedOrders=new Set();

  function _renderOrders(orders){
    var c=document.getElementById("orders-c");if(!c)return;
    if(!orders.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:13px'>لا نتائج</div>";return;}
    var rf=document.getElementById("ord-refresh");
    if(rf)rf.textContent="("+orders.length+" — فلترة)";
    var STATUS_MAP2={processing:"قيد المعالجة",shipped:"تم الشحن",delivered:"تم التوصيل",returned:"مُرتجعة"};
    var toolbar="<div id='bulk-toolbar' style='display:flex;align-items:center;gap:8px;padding:7px 10px;margin-bottom:8px;background:rgba(168,85,247,.06);border:1px solid rgba(168,85,247,.1);border-radius:9px;flex-wrap:wrap;position:sticky;top:0;z-index:2;backdrop-filter:blur(8px)'>"
      +"<label style='display:flex;align-items:center;gap:5px;font-size:11px;color:var(--mu);cursor:pointer'>"
      +"<input type='checkbox' id='bulk-sel-all' style='accent-color:#a855f7;cursor:pointer'> تحديد الكل</label>"
      +"<span id='bulk-count' style='font-size:10px;color:rgba(192,132,252,.7)'>0 محدد</span>"
      +"<button class='aact e' id='bulk-print-btn' style='font-size:10px;margin-right:auto' disabled>طباعة المحدد</button>"
      +"</div>";
    c.innerHTML=toolbar+orders.map(function(o){
      var ih=(o.items||[]).map(function(it){
        return "<div class='oc-pi'>"+(it.img?"<img class='oc-pimg' src='"+_esc(it.img)+"' loading='lazy'>":"")
          +"<span class='oc-pn'>"+_esc(it.name||"")+" x"+it.qty+"</span></div>";
      }).join("");
      var stOpts=["processing","shipped","delivered","returned"].map(function(s){
        return "<option value='"+s+"'"+(o.status===s?" selected":"")+">"+( STATUS_MAP2[s]||s)+"</option>";
      }).join("");
      var isChk=_selectedOrders.has(o.id);
      return "<div class='oc'><div class='oc-h'>"
        +"<label style='display:flex;align-items:center;gap:5px;cursor:pointer;margin-right:3px'>"
        +"<input type='checkbox' class='ord-chk' data-oid='"+_esc(o.id)+"'"+(isChk?" checked":"")
        +" style='accent-color:#a855f7;cursor:pointer;flex-shrink:0'></label>"
        +"<span class='oc-id'>"+_esc(o.id)+"</span>"
        +(o.repeated?"<span class='rep-badge'>تكرار</span>":"")
        +(o.confirmed?"<span class='s-ok'>مؤكدة</span>":"<span class='s-no'>بانتظار</span>")+"</div>"
        +"<div class='oc-ig'>"
        +"<div class='oc-if'><small>الاسم</small><span>"+_esc(o.name||"")+"</span></div>"
        +"<div class='oc-if'><small>الهاتف</small><span>"+_esc(o.phone1||"")+"</span></div>"
        +"<div class='oc-if'><small>الولاية</small><span>"+_esc(o.wilaya||"")+" / "+_esc(o.commune||"")+"</span></div>"
        +"<div class='oc-if'><small>التاريخ</small><span>"+new Date(o.date).toLocaleDateString("ar-DZ")+"</span></div></div>"
        +"<div class='oc-pl'>"+ih+"</div>"
        +"<div class='oc-ft'>"
        +"<span style='font-family:Georgia,serif;color:rgba(192,132,252,.9)'>"+_fmt(o.total||0)+"</span>"
        +"<select class='status-sel' data-oid='"+_esc(o.id)+"'>"+stOpts+"</select>"
        +(o.confirmed
          ?"<button class='aact' data-conf='"+_esc(o.id)+"' data-val='false'>إلغاء</button>"
          :"<button class='aact e' data-conf='"+_esc(o.id)+"' data-val='true'>تأكيد</button>")
        +"<button class='aact' data-invoice='"+_esc(o.id)+"'>فاتورة</button>"
        +"<button class='aact d' data-delord='"+_esc(o.id)+"'>حذف</button>"
        +"</div>"
        /* م12: Audit Trail — يُعرض إذا وُجد سجل تغييرات */
        +(o.auditLog&&o.auditLog.length
          ?"<details class='audit-trail'><summary style='font-size:9px;color:var(--mu);cursor:pointer;padding:5px 10px;list-style:none'>سجل التغييرات ("+o.auditLog.length+")</summary>"
            +"<div style='padding:5px 10px 8px'>"
            +o.auditLog.map(function(ae){
              var dt=new Date(ae.t).toLocaleString("ar-DZ",{day:"2-digit",month:"2-digit",hour:"2-digit",minute:"2-digit"});
              var chg=(ae.changes||[]).map(function(c){
                return c.f==="status"?"الحالة: "+_esc(c.from||"")+" → "+_esc(c.to||"")
                      :c.f==="confirmed"?"تأكيد: "+(c.to?"نعم":"لا")
                      :c.f==="note"?"تعديل ملاحظة":_esc(c.f);
              }).join(" | ");
              return "<div style='font-size:9px;color:var(--mu);padding:2px 0;border-bottom:1px solid rgba(255,255,255,.03)'>"
                +"<span style='color:rgba(168,85,247,.5)'>"+dt+"</span>"
                +(chg?"<span style='margin-right:6px;color:rgba(255,255,255,.4)'>"+chg+"</span>":"")
                +"</div>";
            }).join("")
            +"</div></details>"
          :"")
        +"</div>";
    }).join("");
    function _updBulkUI(){
      var cnt=document.getElementById("bulk-count");
      var pbtn=document.getElementById("bulk-print-btn");
      var n=_selectedOrders.size;
      if(cnt)cnt.textContent=n+" محدد";
      if(pbtn){pbtn.disabled=n===0;pbtn.textContent=n>0?"طباعة "+n+" طلبية":"طباعة المحدد";}
    }
    c.querySelectorAll(".ord-chk").forEach(function(chk){
      chk.addEventListener("change",function(){
        var oid=chk.getAttribute("data-oid");
        if(chk.checked)_selectedOrders.add(oid);else _selectedOrders.delete(oid);
        _updBulkUI();
        var sa=document.getElementById("bulk-sel-all");
        if(sa)sa.indeterminate=_selectedOrders.size>0&&_selectedOrders.size<orders.length;
      });
    });
    var selAll=document.getElementById("bulk-sel-all");
    if(selAll){
      selAll.addEventListener("change",function(){
        c.querySelectorAll(".ord-chk").forEach(function(chk){
          var oid=chk.getAttribute("data-oid");
          chk.checked=selAll.checked;
          if(selAll.checked)_selectedOrders.add(oid);else _selectedOrders.delete(oid);
        });
        _updBulkUI();
      });
    }
    var pbtn=document.getElementById("bulk-print-btn");
    if(pbtn){
      pbtn.addEventListener("click",function(){
        if(!_selectedOrders.size)return;
        var ids=Array.from(_selectedOrders).slice(0,50);
        var w=window.open("","_blank","width=960,height=720,scrollbars=yes");
        if(!w){_toast("السماح بالنوافذ المنبثقة مطلوب");return;}
        w.document.write(
          '<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8">'
          +'<title>طباعة جماعية — '+ids.length+' طلبية</title>'
          +'<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#f5f5f5}'
          +'.ctrl{text-align:center;padding:12px;background:#fff;border-bottom:1px solid #eee;display:flex;gap:8px;justify-content:center;position:sticky;top:0;z-index:10}'
          +'.ctrl button{padding:8px 18px;border-radius:7px;border:1px solid #ddd;cursor:pointer;font-size:13px}'
          +'.inf{text-align:center;padding:6px;font-size:11px;color:#888;background:#fff9e6}'
          +'.pw{page-break-after:always;border-bottom:3px solid #e5e7eb;padding-bottom:10px;margin-bottom:10px}'
          +'@media print{.ctrl,.inf{display:none!important}.pw{page-break-after:always;border:none}}'
          +'</style></head><body>'
          +'<div class="ctrl">'
          +'<button onclick="window.print()" style="background:#6d28d9;color:#fff;border-color:#6d28d9">طباعة الكل ('+ids.length+' فاتورة)</button>'
          +'<button onclick="window.close()" style="background:#eee;color:#333">إغلاق</button>'
          +'</div>'
          +'<div class="inf" id="inf">جاري تحميل الفواتير...</div>'
          +'<div id="ct"></div>'
          +'<script>(function(){'
          +'var ids='+JSON.stringify(ids)+';'
          +'var done=0,total=ids.length,ct=document.getElementById("ct"),inf=document.getElementById("inf");'
          +'function next(i){if(i>=total){if(inf)inf.textContent="تم تحميل "+total+" فاتورة — جاهز للطباعة";return;}'
          +'fetch("/invoice?id="+encodeURIComponent(ids[i])+"&pt=1")'
          +'.then(function(r){return r.text();})'
          +'.then(function(h){var d=document.createElement("div");d.className="pw";'
          +'var m=h.match(/<body[\s\S]*?>([\s\S]*?)<\/body>/i);'
          +'d.innerHTML=m?m[1].replace(/<script[\s\S]*?<\/script>/gi,""):h;'
          +'ct.appendChild(d);done++;if(inf)inf.textContent="تحميل: "+done+"/"+total;'
          +'setTimeout(function(){next(i+1);},90);})'
          +'.catch(function(){done++;setTimeout(function(){next(i+1);},90);});}'
          +'next(0);})()'
          +'<\/script></body></html>'
        );
        w.document.close();
        _toast("جاري تحضير "+ids.length+" فاتورة...");
      });
    }
    _updBulkUI();
    c.querySelectorAll(".status-sel").forEach(function(sel){
      sel.addEventListener("change",function(){
        _api("/api/orders",{method:"PATCH",body:JSON.stringify({id:sel.getAttribute("data-oid"),status:sel.value})})
          .then(function(){_toast("تم التحديث");});
      });
    });
    c.querySelectorAll("[data-conf]").forEach(function(btn){
      btn.addEventListener("click",function(){
        var oid=btn.getAttribute("data-conf");var val=btn.getAttribute("data-val")==="true";
        _api("/api/orders",{method:"PATCH",body:JSON.stringify({id:oid,confirmed:val})})
          .then(function(){_loadOrders();});
      });
    });
    c.querySelectorAll("[data-invoice]").forEach(function(btn){
      btn.addEventListener("click",function(){
        window.open("/invoice?id="+encodeURIComponent(btn.getAttribute("data-invoice")),"_blank");
      });
    });
    c.querySelectorAll("[data-delord]").forEach(function(btn){
      btn.addEventListener("click",function(){
        if(!confirm("حذف؟"))return;
        var oid=btn.getAttribute("data-delord");
        _api("/api/orders?id="+oid,{method:"DELETE"}).then(function(){
          _selectedOrders.delete(oid);
          _ordersCache=_ordersCache.filter(function(o){return o.id!==oid;});
          _renderOrders(_ordersCache);
        });
      });
    });
  }
    function _clearOrders(){if(!confirm("حذف كل الطلبيات؟"))return;_api("/api/orders",{method:"DELETE"}).then(function(){_loadOrders();_toast("تم الحذف");}).catch(function(){_toast("خطا");});}
  /* -- م8 Phase 3: instant filter + full URL state (status, conf, rep, query, wilaya, phone) -- */
  var _filterDebounce=null;
  function _filterOrders(){
    var stV=(document.getElementById("ord-f-status")||{}).value||"";
    var cfV=(document.getElementById("ord-f-conf")||{}).value||"";
    var repV=(document.getElementById("ord-f-rep")||{}).value||"";
    var qV=((document.getElementById("ord-f-q")||{}).value||"").trim().toLowerCase();
    var wilV=((document.getElementById("ord-f-wilaya")||{}).value||"").trim().toLowerCase();
    var phV=((document.getElementById("ord-f-phone")||{}).value||"").trim();
    try{
      var params=new URLSearchParams(window.location.search);
      if(stV)params.set("ofs",stV);else params.delete("ofs");
      if(cfV)params.set("ofc",cfV);else params.delete("ofc");
      if(repV)params.set("ofr",repV);else params.delete("ofr");
      if(qV)params.set("ofq",qV);else params.delete("ofq");
      if(wilV)params.set("ofw",wilV);else params.delete("ofw");
      if(phV)params.set("ofp",phV);else params.delete("ofp");
      var nu=window.location.pathname+(params.toString()?"?"+params.toString():"");
      window.history.replaceState(null,"",nu);
    }catch(e){}
    var filtered=_ordersCache.filter(function(o){
      if(stV&&o.status!==stV)return false;
      if(cfV==="1"&&!o.confirmed)return false;
      if(cfV==="0"&&o.confirmed)return false;
      if(repV==="1"&&!o.repeated)return false;
      if(repV==="0"&&o.repeated)return false;
      if(wilV){
        var w=(o.wilaya||"").toLowerCase();
        if(!w.includes(wilV))return false;
      }
      if(phV){
        var ph=(o.phone1||"")+(o.phone2||"");
        if(!ph.includes(phV))return false;
      }
      if(qV){
        var hay=(o.name||"").toLowerCase()+(o.phone1||"")+(o.phone2||"")
                +(o.id||"").toLowerCase()+(o.wilaya||"").toLowerCase()
                +(o.commune||"").toLowerCase()+(o.status||"").toLowerCase();
        if(!hay.includes(qV))return false;
      }
      return true;
    });
    _renderOrders(filtered);
  }
  function _restoreOrderFilters(){
    try{
      var p=new URLSearchParams(window.location.search);
      var ofs=p.get("ofs"),ofc=p.get("ofc"),ofr=p.get("ofr"),ofq=p.get("ofq");
      var ofw=p.get("ofw"),ofp=p.get("ofp");
      var s1=document.getElementById("ord-f-status"),s2=document.getElementById("ord-f-conf");
      var s3=document.getElementById("ord-f-rep"),s4=document.getElementById("ord-f-q");
      var s5=document.getElementById("ord-f-wilaya"),s6=document.getElementById("ord-f-phone");
      if(ofs&&s1)s1.value=ofs;
      if(ofc&&s2)s2.value=ofc;
      if(ofr&&s3)s3.value=ofr;
      if(ofq&&s4)s4.value=ofq;
      if(ofw&&s5)s5.value=ofw;
      if(ofp&&s6)s6.value=ofp;
      if(ofs||ofc||ofr||ofq||ofw||ofp)_filterOrders();
    }catch(e){}
  }
  /* -- m10: geographical accordion -- 58 wilayas -- */
  function _groupOrders(){
    var source=_ordersCache.slice();
    var stV=(document.getElementById("ord-f-status")||{}).value||"";
    var cfV=(document.getElementById("ord-f-conf")||{}).value||"";
    var repV=(document.getElementById("ord-f-rep")||{}).value||"";
    var qV=((document.getElementById("ord-f-q")||{}).value||"").trim().toLowerCase();
    if(stV||cfV||repV||qV){
      source=source.filter(function(o){
        if(stV&&o.status!==stV)return false;
        if(cfV==="1"&&!o.confirmed)return false;
        if(cfV==="0"&&o.confirmed)return false;
        if(repV==="1"&&!o.repeated)return false;
        if(repV==="0"&&o.repeated)return false;
        if(qV){
          var hay=(o.name||"").toLowerCase()+(o.phone1||"")+(o.phone2||"")
                  +(o.id||"").toLowerCase()+(o.wilaya||"").toLowerCase()
                  +(o.commune||"").toLowerCase()+(o.status||"").toLowerCase();
          if(!hay.includes(qV))return false;
        }
        return true;
      });
    }
    if(!source.length){_toast("لا توجد طلبيات مطابقة");return;}
    var grp={};
    source.forEach(function(o){
      var w=o.wilaya||"غير محدد";
      if(!grp[w])grp[w]={orders:[],total:0,confirmed:0,revenue:0};
      grp[w].orders.push(o);grp[w].total++;
      if(o.confirmed){grp[w].confirmed++;grp[w].revenue+=(o.total||0);}
    });
    var sorted=Object.entries(grp).sort(function(a,b){return b[1].total-a[1].total;});
    var SM={processing:"قيد المعالجة",shipped:"تم الشحن",delivered:"تم التوصيل",returned:"مُرتجعة"};
    var totalRev=source.filter(function(o){return o.confirmed;}).reduce(function(a,o){return a+(o.total||0);},0);
    var html="<div style='margin-bottom:9px;padding:8px 11px;background:rgba(168,85,247,.06);border:1px solid rgba(168,85,247,.12);border-radius:9px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px;font-size:10px;color:var(--mu)'>"
      +"<span>"+sorted.length+" ولاية — "+source.length+" طلبية</span>"
      +"<span style='color:rgba(192,132,252,.8)'>"+_fmt(totalRev)+" إيراد مؤكد</span>"
      +"<button class='aact' id='grp-collapse-all' style='font-size:9px;padding:2px 8px'>طي الكل</button>"
      +"</div>";
    html+=sorted.map(function(entry){
      var wn=entry[0],d=entry[1];
      var pct=d.total?Math.round(d.confirmed/d.total*100):0;
      var pc=pct>=70?"rgba(74,222,128,.55)":pct>=40?"rgba(251,191,36,.55)":"rgba(239,68,68,.45)";
      var smry="<span style='font-size:12px;color:rgba(192,132,252,.9);font-weight:600'>"+_esc(wn)+"</span>"
        +"<span style='background:rgba(168,85,247,.12);border:1px solid rgba(168,85,247,.2);border-radius:12px;padding:1px 8px;font-size:10px;color:rgba(192,132,252,.7)'>"+d.total+" طلبية</span>"
        +"<span style='font-size:10px;color:rgba(74,222,128,.7)'>"+_fmt(d.revenue)+"</span>"
        +"<span style='font-size:9px;color:var(--mu)'>تاكيد: "+pct+"%</span>"
        +"<div style='flex:1;min-width:50px;height:3px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden'>"
        +"<div style='width:"+pct+"%;height:100%;background:"+pc+";border-radius:2px'></div></div>";
      var rows=d.orders.map(function(o){
        var sc={processing:"rgba(251,191,36,.75)",shipped:"rgba(59,130,246,.75)",delivered:"rgba(74,222,128,.75)",returned:"rgba(239,68,68,.75)"}[o.status]||"rgba(168,85,247,.6)";
        return "<div style='display:grid;grid-template-columns:auto 1fr auto auto;gap:6px;align-items:center;padding:6px 10px;border-bottom:1px solid rgba(255,255,255,.03);font-size:10px'>"
          +"<span style='font-family:monospace;color:rgba(168,85,247,.5);font-size:9px'>"+_esc((o.id||"").slice(-6))+"</span>"
          +"<div><div style='color:rgba(255,255,255,.65)'>"+_esc(o.name||"")+"</div>"
          +"<div style='color:var(--mu);font-size:9px'>"+_esc(o.phone1||"")+" · "+_esc(o.commune||"")+"</div></div>"
          +"<span style='font-family:Georgia,serif;color:rgba(192,132,252,.8);white-space:nowrap'>"+_fmt(o.total||0)+"</span>"
          +"<span style='padding:2px 6px;border-radius:5px;background:"+sc+"22;color:"+sc+";font-size:9px;white-space:nowrap'>"+_esc(SM[o.status]||o.status||"")+"</span>"
          +"</div>";
      }).join("");
      return "<details class='wly-acc' style='margin-bottom:5px;background:rgba(168,85,247,.025);border:1px solid rgba(168,85,247,.09);border-radius:10px;overflow:hidden'>"
        +"<summary style='padding:9px 12px;cursor:pointer;list-style:none;display:flex;align-items:center;gap:7px;flex-wrap:wrap;user-select:none;-webkit-tap-highlight-color:transparent'>"
        +"<span class='wly-arr' style='font-size:8px;color:var(--mu);display:inline-block;transition:transform .18s;flex-shrink:0'>&#9650;</span>"
        +smry+"</summary>"
        +"<div style='border-top:1px solid rgba(168,85,247,.07)'>"+rows+"</div>"
        +"</details>";
    }).join("");
    var c=document.getElementById("orders-c");if(!c)return;
    c.innerHTML=html;
    var colBtn=document.getElementById("grp-collapse-all");
    if(colBtn){
      var _ao=false;
      colBtn.addEventListener("click",function(){
        _ao=!_ao;
        c.querySelectorAll(".wly-acc").forEach(function(d){if(_ao)d.setAttribute("open","");else d.removeAttribute("open");});
        colBtn.textContent=_ao?"طي الكل":"فتح الكل";
      });
    }
    c.querySelectorAll(".wly-acc").forEach(function(det){
      det.addEventListener("toggle",function(){
        var arr=det.querySelector(".wly-arr");
        if(arr)arr.style.transform=det.open?"rotate(180deg)":"rotate(0deg)";
      });
    });
    var rf=document.getElementById("ord-refresh");
    if(rf)rf.textContent="("+source.length+" — تجميع ولايات)";
  }
  function _showCsvCols(){
    var cols=["id","name","phone1","phone2","wilaya","commune","items","total","fee","status","confirmed","repeated","pay","coupon","note","date"];
    var labels={id:"رقم",name:"الاسم",phone1:"هاتف 1",phone2:"هاتف 2",wilaya:"ولاية",commune:"بلدية",items:"منتجات",total:"مجموع",fee:"شحن",status:"حالة",confirmed:"مؤكدة",repeated:"مكررة",pay:"دفع",coupon:"كوبون",note:"ملاحظة",date:"تاريخ"};
    var html="<div style='position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:10000;display:flex;align-items:center;justify-content:center' id='csv-col-ov'>"
      +"<div style='background:#0a0016;border:1px solid rgba(168,85,247,.3);border-radius:12px;padding:18px 20px;max-width:320px;width:90%'>"
      +"<div style='font-size:12px;color:rgba(192,132,252,.9);margin-bottom:12px'>اختر الأعمدة</div>"
      +"<div style='display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:12px'>"
      +cols.map(function(k){
        return "<label style='display:flex;align-items:center;gap:5px;font-size:11px;color:var(--mu);cursor:pointer'>"
          +"<input type='checkbox' class='csv-col-chk' data-k='"+k+"' checked style='accent-color:#a855f7'> "+(labels[k]||k)+"</label>";
      }).join("")+"</div>"
      +"<div style='display:flex;gap:7px'>"
      +"<button class='aact e' id='csv-col-ok' style='flex:1'>تصدير</button>"
      +"<button class='aact' id='csv-col-cancel' style='flex:1'>إلغاء</button>"
      +"</div></div></div>";
    document.body.insertAdjacentHTML("beforeend",html);
    document.getElementById("csv-col-cancel").onclick=function(){var ov=document.getElementById("csv-col-ov");if(ov)ov.remove();};
    document.getElementById("csv-col-ok").onclick=function(){
      var sel=[];document.querySelectorAll(".csv-col-chk:checked").forEach(function(chk){sel.push(chk.getAttribute("data-k"));});
      var ov=document.getElementById("csv-col-ov");if(ov)ov.remove();
      _exportCSV(sel);
    };
  }
  function _exportCSV(cols){
    if(!_ordersCache.length){_toast("لا طلبيات");return;}
    var ALL_COLS=[
      {k:"id",l:"رقم",fn:function(o){return o.id;}},
      {k:"name",l:"الاسم",fn:function(o){return o.name||"";}},
      {k:"phone1",l:"هاتف 1",fn:function(o){return o.phone1||"";}},
      {k:"phone2",l:"هاتف 2",fn:function(o){return o.phone2||"--";}},
      {k:"wilaya",l:"ولاية",fn:function(o){return o.wilaya||"";}},
      {k:"commune",l:"بلدية",fn:function(o){return o.commune||"";}},
      {k:"items",l:"منتجات",fn:function(o){return (o.items||[]).map(function(it){return it.name+"x"+it.qty;}).join(" | ");}},
      {k:"total",l:"مجموع دج",fn:function(o){return o.total||0;}},
      {k:"fee",l:"شحن",fn:function(o){return o.fee||0;}},
      {k:"status",l:"حالة شحن",fn:function(o){return o.status||"";}},
      {k:"confirmed",l:"مؤكدة",fn:function(o){return o.confirmed?"نعم":"لا";}},
      {k:"repeated",l:"مكررة",fn:function(o){return o.repeated?"نعم":"لا";}},
      {k:"pay",l:"دفع",fn:function(o){return o.payMethod||"cod";}},
      {k:"coupon",l:"كوبون",fn:function(o){return o.couponCode||"";}},
      {k:"note",l:"ملاحظة",fn:function(o){return o.note||"";}},
      {k:"date",l:"تاريخ",fn:function(o){return new Date(o.date).toLocaleString("ar-DZ");}}
    ];
    var usedCols=cols&&cols.length?ALL_COLS.filter(function(c){return cols.indexOf(c.k)!==-1;}):ALL_COLS;
    var h=usedCols.map(function(c){return c.l;});
    var rows=_ordersCache.map(function(o){
      return usedCols.map(function(col){return '"'+String(col.fn(o)||"").replace(/"/g,'""')+'"';});
    });
    var csv="\uFEFF"+h.join(",")+"\\n"+rows.map(function(r){return r.join(",");}).join("\\n");
    var blob=new Blob([csv],{type:"text/csv;charset=utf-8"});
    var a=document.createElement("a");a.href=URL.createObjectURL(blob);
    a.download="orders_"+new Date().toISOString().slice(0,10)+".csv";
    document.body.appendChild(a);a.click();document.body.removeChild(a);
    _toast("تم تصدير "+_ordersCache.length+" طلبية");
  }
    function _loadVisitors(){
    var vc=document.getElementById("visitors-c");
    if(vc)vc.innerHTML="<div style='color:var(--mu);font-size:12px'><span class='spin'></span></div>";
    _api("/api/analytics").then(function(r){return r.json();}).then(function(d){
      var c=document.getElementById("visitors-c");if(!c)return;
      var vs=d.visitors||[];
      if(!vs.length){c.innerHTML="<div style='color:var(--mu);font-size:12px'>لا توجد بيانات</div>";return;}
      var tb=d.tierBreakdown||{high:0,mid:0,low:0};
      var bmap=d.browserMap||{};
      var tierHTML="<div style='display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-bottom:12px'>"
        +"<div style='background:rgba(74,222,128,.08);border:1px solid rgba(74,222,128,.2);border-radius:8px;padding:9px;text-align:center'><div style='font-size:18px;font-weight:700;color:rgba(74,222,128,.9)'>"+tb.high+"</div><div style='font-size:9px;color:var(--mu)'>عالي</div></div>"
        +"<div style='background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.2);border-radius:8px;padding:9px;text-align:center'><div style='font-size:18px;font-weight:700;color:rgba(251,191,36,.9)'>"+tb.mid+"</div><div style='font-size:9px;color:var(--mu)'>متوسط</div></div>"
        +"<div style='background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:8px;padding:9px;text-align:center'><div style='font-size:18px;font-weight:700;color:rgba(239,68,68,.9)'>"+tb.low+"</div><div style='font-size:9px;color:var(--mu)'>منخفض</div></div>"
        +"</div>";
      var browsers=Object.entries(bmap).sort(function(a,b){return b[1]-a[1];});
      var totalBr=browsers.reduce(function(a,b){return a+b[1];},0)||1;
      var brHTML="<div style='margin-bottom:12px'><div style='font-size:10px;color:var(--mu);margin-bottom:6px'>توزيع المتصفحات</div>"
        +browsers.slice(0,6).map(function(e){
          var pct=Math.round(e[1]/totalBr*100);
          return "<div style='display:flex;align-items:center;gap:7px;margin-bottom:5px'>"
            +"<div style='width:60px;font-size:10px;color:var(--dim);text-align:right'>"+_esc(e[0])+"</div>"
            +"<div style='flex:1;background:rgba(255,255,255,.05);border-radius:3px;height:7px'><div style='width:"+pct+"%;height:100%;background:rgba(168,85,247,.5);border-radius:3px'></div></div>"
            +"<div style='font-size:9px;color:var(--mu);width:35px'>"+e[1]+" ("+pct+"%)</div></div>";
        }).join("")+"</div>";
      var TIER_C={high:"rgba(74,222,128,.8)",mid:"rgba(251,191,36,.7)",low:"rgba(239,68,68,.7)"};
      var visHTML=vs.slice(0,50).map(function(v){
        var tc=TIER_C[v.tier]||"rgba(168,85,247,.6)";
        return "<div class='vr' style='display:grid;grid-template-columns:auto 1fr auto auto;gap:8px;align-items:center;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.04)'>"
          +"<span style='font-family:monospace;font-size:9px;color:rgba(168,85,247,.5)'>"+_esc((v.vid||"").slice(-6))+"</span>"
          +"<div><div style='font-size:10px;color:rgba(255,255,255,.65)'>"+_esc(v.dev||"")+" · "+_esc(v.browser||"")+"</div>"
          +"<div style='font-size:9px;color:var(--mu)'>"+_esc(v.os||"")+" · "+_esc(v.source||"Direct")+"</div></div>"
          +"<span style='font-size:10px;padding:2px 7px;border-radius:5px;background:"+tc+"22;color:"+tc+"'>"
          +(v.tier==="high"?"عالي":v.tier==="low"?"منخفض":"متوسط")+"</span>"
          +"<span style='font-size:11px;font-family:Georgia,serif;color:rgba(192,132,252,.8)'>"+v.count+"</span></div>";
      }).join("");
      c.innerHTML=tierHTML+brHTML+"<div style='font-size:10px;color:var(--mu);margin-bottom:6px'>آخر 50 زائر</div>"+visHTML;
    }).catch(function(){});
  }
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
      if(n3)n3.addEventListener("click",function(){
        _chkGoTo(4);
        /* م5: تفعيل فحص الكوبون الفوري عند الوصول لخطوة الدفع */
        _initLiveCouponCheck();
      });
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
      // _loadSettings أولاً (async) ثم _restoreDiscount بعد اكتمالها
      _loadSettings(_restoreDiscount);
      _updCart();
      _showMystery();
      _initExitIntent();
      _initStarRating();
      _initKeyboardShortcuts();
      _initFullscreen();
      _initLang();
    }catch(e){console.error("WOW init error:",e);}
  });

  // ══ COUPONS ══════════════════════════════════════════════════════
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
          +(cp.minCart?"<br><span style='font-size:9px'>حد سلة: "+cp.minCart.toLocaleString()+" دج</span>":"")
          +(cp.wilayaList&&cp.wilayaList.length?"<br><span style='font-size:9px;color:rgba(168,85,247,.6)'>ولايات: "+cp.wilayaList.slice(0,3).join(",")+( cp.wilayaList.length>3?"...":"")+"</span>":"")
          +(cp.expiresAt?"<br><span style='font-size:9px'>حتى: "+new Date(cp.expiresAt).toLocaleDateString("ar-DZ")+"</span>":"")+"</div>"
          +"<button class='aact"+(cp.active&&!expired&&!exhausted?" d":"")+' data-cp-toggle="'+cp.id+'" data-cp-active="'+cp.active+'">'+
            (cp.active&&!expired&&!exhausted?"تعطيل":"تفعيل")+"</button>"
          +"<button class='aact d' data-cp-del='"+cp.id+"'>X</button>"
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
    var minCart=parseFloat((document.getElementById("cp-min")||{}).value)||0;
    var wlRaw=((document.getElementById("cp-wilayas")||{}).value||"").trim();
    var wilayaList=wlRaw?wlRaw.split(",").map(function(x){return x.trim();}).filter(Boolean):[];
    _api("/api/coupons",{method:"POST",body:JSON.stringify({code,discType:type,discVal:val,maxUses:uses,minCart:minCart,wilayaList:wilayaList,expiresAt:exp?new Date(exp).toISOString():null})})
      .then(function(r){return r.json();}).then(function(d){
        if(d.error){_toast(d.error);return;}
        _toast("تم إنشاء الكوبون: "+d.code);
        ["cp-code","cp-val","cp-uses","cp-exp"].forEach(function(id){var el=document.getElementById(id);if(el)el.value="";});
        _loadCoupons();
      }).catch(function(){_toast("خطأ");});
  }

  // ══ م٥ COUPON: live Ajax check + debounce 900ms ═════════════════════
  var _liveCouponTimer=null;
  var _liveCouponBound=false;
  var _lastCheckedCode="";

  /* ربط الفحص الفوري بحقل الكوبون — يُستدعى مرة واحدة عند فتح الدفع */
  function _initLiveCouponCheck(){
    if(_liveCouponBound)return;
    var el=document.getElementById("o-coupon");
    if(!el)return;
    _liveCouponBound=true;
    el.addEventListener("input",function(){
      var raw=el.value.trim().toUpperCase();
      if(!raw){
        clearTimeout(_liveCouponTimer);
        _lastCheckedCode="";
        _couponApplied=null;
        var row2=document.getElementById("op-coupon-row");
        if(row2)row2.style.display="none";
        _updCartTotals();
        el.style.borderColor="";
        var clearStatus=document.getElementById("coupon-status");
        if(clearStatus)clearStatus.textContent="";
        return;
      }
      if(raw===_lastCheckedCode)return;
      el.style.borderColor="rgba(168,85,247,.35)";
      var liveStatus=document.getElementById("coupon-status");
      if(liveStatus)liveStatus.textContent="جاري التحقق...";
      clearTimeout(_liveCouponTimer);
      _liveCouponTimer=setTimeout(function(){
        _liveCouponTimer=null;
        _lastCheckedCode=raw;
        _checkCouponAjax(raw,false);
      },900);
    });
    el.addEventListener("keydown",function(e){
      if(e.key==="Enter"){
        e.preventDefault();
        clearTimeout(_liveCouponTimer);
        _liveCouponTimer=null;
        var raw2=el.value.trim().toUpperCase();
        if(raw2)_checkCouponAjax(raw2,true);
      }
    });
  }

  function _checkCouponAjax(code,isManual){
    var el=document.getElementById("o-coupon");
    var st=document.getElementById("coupon-status");
    var sub=_cart.reduce(function(a,it){return a+(it.price*(1-(it.discount||0)/100)*it.qty);},0);
    var curWilaya=(document.getElementById("o-wilaya")||{}).value||"";
    _api("/api/coupon-check",{method:"POST",body:JSON.stringify({code:code,sub:Math.round(sub),wilaya:curWilaya})})
      .then(function(r){return r.json();})
      .then(function(d){
        var statusColor=d.ok?"rgba(74,222,128,.5)":"rgba(239,68,68,.4)";
        if(el)el.style.borderColor=statusColor;
        if(st)st.textContent=d.msg||(d.ok?"تم تطبيق الخصم":"كود غير صالح");
        if(!d.ok){
          _couponApplied=null;
          var badCouponRow=document.getElementById("op-coupon-row");
          if(badCouponRow)badCouponRow.style.display="none";
          _updCartTotals();
          return;
        }
        _couponApplied={code:d.code,discAmt:d.discAmt,discType:d.discType,discVal:d.discVal};
        var goodCouponRow=document.getElementById("op-coupon-row");
        var lbl=document.getElementById("op-coupon-lbl");
        var val=document.getElementById("op-coupon-val");
        if(goodCouponRow)goodCouponRow.style.display="flex";
        if(lbl)lbl.textContent="كوبون ("+_esc(d.code)+")";
        if(val)val.textContent="- "+_fmt(d.discAmt)+" دج";
        _updCartTotals();
        if(isManual)_toast(d.msg||"تم تطبيق الخصم");
      })
      .catch(function(){
        if(el)el.style.borderColor="rgba(239,68,68,.4)";
        if(st)st.textContent="خطأ في التحقق";
        if(isManual)_toast("خطأ في التحقق");
      });
  }

  function _applyCoupon(){
    var el=document.getElementById("o-coupon");if(!el)return;
    var code=el.value.trim().toUpperCase();
    if(!code){_toast("أدخل كود الخصم");return;}
    clearTimeout(_liveCouponTimer);
    _liveCouponTimer=null;
    _lastCheckedCode=code;
    _checkCouponAjax(code,true);
  }

  // ══ ARCHIVE ══════════════════════════════════════════════════════
  var _archiveSelected=new Set();
  function _restoreSelectedArchive(){
    if(!_archiveSelected.size){_toast("حدد منتجا أولا");return;}
    var ids=Array.from(_archiveSelected);
    Promise.all(ids.map(function(id){
      return _api("/api/products/archive",{method:"POST",body:JSON.stringify({id:id,action:"restore"})});
    })).then(function(){
      _archiveSelected.clear();
      _loadArchive();_loadAdmProds();
      _toast("تمت استعادة "+ids.length+" منتج");
    }).catch(function(){_toast("خطأ");});
  }
  function _loadArchive(){
    var c=document.getElementById("archive-c");if(!c)return;
    c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'><span class='spin'></span></div>";
    _api("/api/products/archive").then(function(r){return r.json();}).then(function(prods){
      if(!prods.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>لا توجد منتجات مؤرشفة</div>";return;}
      var saBtn=document.getElementById("archive-sel-all");
      var restBtn=document.getElementById("archive-restore-all-btn");
      _archiveSelected.clear();
      function _updArchUI(){
        if(restBtn)restBtn.style.display=_archiveSelected.size?"":"none";
        if(restBtn)restBtn.textContent="استعادة "+_archiveSelected.size+" منتج";
      }
      c.innerHTML=prods.map(function(p){
        var img=(p.images&&p.images[0])||"";
        return "<div class='arch-row'>"
          +"<label style='display:flex;align-items:center;cursor:pointer'>"
          +"<input type='checkbox' class='arch-chk' data-pid='"+p.id+"' style='accent-color:#a855f7;cursor:pointer'></label>"
          +(img?"<img src='"+_esc(img)+"' style='width:44px;height:54px;object-fit:cover;border-radius:5px'>":"<div style='width:44px;height:54px;background:rgba(168,85,247,.06);border-radius:5px'></div>")
          +"<div><div style='font-size:12px;color:var(--dim);margin-bottom:3px'>"+_esc(p.name||"")+"</div>"
          +"<div style='font-size:10px;color:var(--mu)'>"+_fmt(p.price||0)+" دج — أُرشف: "+new Date(p.archivedAt||0).toLocaleDateString("ar-DZ")+"</div></div>"
          +"<button class='aact e' data-restore='"+p.id+"'>استعادة</button></div>";
      }).join("");
      c.querySelectorAll(".arch-chk").forEach(function(chk){
        chk.addEventListener("change",function(){
          var pid=chk.getAttribute("data-pid");
          if(chk.checked)_archiveSelected.add(pid);else _archiveSelected.delete(pid);
          _updArchUI();
        });
      });
      if(saBtn){
        saBtn.onchange=function(){
          c.querySelectorAll(".arch-chk").forEach(function(chk){
            chk.checked=saBtn.checked;
            var pid=chk.getAttribute("data-pid");
            if(saBtn.checked)_archiveSelected.add(pid);else _archiveSelected.delete(pid);
          });
          _updArchUI();
        };
      }
      _updArchUI();
      c.querySelectorAll("[data-restore]").forEach(function(btn){
        btn.addEventListener("click",function(){
          _api("/api/products/archive",{method:"POST",body:JSON.stringify({id:btn.getAttribute("data-restore"),action:"restore"})})
            .then(function(){_loadArchive();_loadAdmProds();_toast("تمت الاستعادة");}).catch(function(){_toast("خطأ");});
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
  function _populateStockProds(){
    var sel=document.getElementById("sh-prod-sel");if(!sel)return;
    _api("/api/products").then(function(r){return r.json();}).then(function(prods){
      sel.innerHTML="<option value=''>اختر منتج...</option>"+(prods||[]).map(function(p){return "<option value='"+p.id+"'>"+_esc(p.name||"")+" ("+(p.quantity!==null&&p.quantity!==undefined?p.quantity:"∞")+")</option>";}).join("");
    }).catch(function(){});
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
        _toast("تمت الإضافة. الرصيد الجديد: "+d.newQty);
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
      _toast("تم حذف "+d.deleted+" سجل. المتبقي: "+d.remaining);
      _loadVisitors();
    }).catch(function(){_toast("خطأ في الحذف");});
  }

  // ══ _updCartTotals patch for coupon ═════════════════════════════
  var _origUpdCartTotals=null;
  function _updCartTotals(){_updPreview();}

  
  // ══ FLASH SALES (admin) ══════════════════════════════════════════
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
          +"<button class='aact d' data-del-fs='"+f.id+"'>X</button>"
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
      _toast("Flash Sale أُنشئ!");_loadFlashSales();
    }).catch(function(){_toast("خطأ");});
  }

  // ══ FLASH SALE TIMER on product cards ════════════════════════════
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

  // ══ BUNDLES (admin) ══════════════════════════════════════════════
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
          +"<button class='aact d' data-del-bundle='"+b.id+"'>X</button>"
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
        _toast("تم إنشاء الحزمة!");
        ["bd-name","bd-prods","bd-disc"].forEach(function(id){var e=document.getElementById(id);if(e)e.value="";});
        _loadBundles();
      }).catch(function(){_toast("خطأ");});
  }

  // ══ BUNDLES (storefront) ═════════════════════════════════════════
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
    _toast(_esc(b.name||"")+" — "+_esc(names));
  }

  // ══ WAITLIST (storefront) ════════════════════════════════════════
  function _showWaitlist(prod){
    var phone=prompt("أدخل رقم هاتفك لتلقي تنبيه عند توفر المنتج:");
    if(!phone)return;
    _api("/api/waitlist",{method:"POST",body:JSON.stringify({phone:phone.trim(),productId:prod.id,productName:prod.name||""})})
      .then(function(r){return r.json();}).then(function(d){_toast(d.msg||"تم التسجيل");}).catch(function(){_toast("خطأ");});
  }

  // ══ WAITLIST (admin) ════════════════════════════════════════════
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

  // ══ LOYALTY (admin) ═════════════════════════════════════════════
  function _loadLoyalty(){
    var c=document.getElementById("loyalty-c");if(!c)return;
    _api("/api/loyalty").then(function(r){return r.json();}).then(function(list){
      if(!list.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>لا توجد نقاط مسجلة بعد</div>";return;}
      c.innerHTML="<div style='background:rgba(255,255,255,.02);border:1px solid var(--b1);border-radius:9px;overflow:hidden'>"
        +list.slice(0,100).map(function(u){
          return "<div style='display:flex;justify-content:space-between;align-items:center;padding:8px 13px;border-bottom:1px solid rgba(255,255,255,.04);font-size:11px'>"
            +"<div><div style='color:var(--dim)'>"+_esc(u.name||"")+"</div><div style='color:var(--mu);font-size:10px'>"+_esc(u.phone||"")+"</div></div>"
            +"<div class='loyalty-pts-badge' onclick='WOW._viewLoyaltyDetail(\\""+_esc(u.phone)+"\\")' style='cursor:pointer'>⭐ نقاط</div>"
            +"</div>";
        }).join("")+"</div>";
    }).catch(function(){});
  }
  function _viewLoyaltyDetail(phone){
    _api("/api/loyalty?phone="+encodeURIComponent(phone)).then(function(r){return r.json();}).then(function(d){
      alert(phone+"\\n النقاط: "+(d.points||0)+"\\nالمكافأة: "+Math.floor((d.points||0)/10)+" دج خصم");
    }).catch(function(){});
  }

  // ══ REFERRALS (admin) ════════════════════════════════════════════
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

  // ══ REVIEWS (admin) ══════════════════════════════════════════════
  function _loadReviews(){
    var c=document.getElementById("reviews-c");if(!c)return;
    _api("/api/reviews").then(function(r){return r.json();}).then(function(list){
      if(!list.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>لا توجد تقييمات</div>";return;}
      c.innerHTML=list.slice(0,100).map(function(rv){
        var sh="";for(var i=1;i<=5;i++)sh+="<span style='color:"+(i<=(rv.rating||5)?"rgba(251,191,36,.9)":"rgba(255,255,255,.15)")+";font-size:13px'>&#9733;</span>";
        return "<div class='rv-card"+(rv.approved?"":" rv-pending")+"'>"
          +"<div class='rv-card-stars'>"+sh+"</div>"
          +"<div class='rv-card-body'>"+_esc(rv.body||"")+"</div>"
          +"<div style='display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:4px'>"
          +"<div class='rv-card-name'>"+_esc(rv.name||"")+" · "+rv.t.slice(0,10)+(rv.phone?" · "+_esc(rv.phone):"")+"</div>"
          +"<div style='display:flex;gap:5px'>"
          +(rv.approved?"<span style='font-size:9px;color:rgba(74,222,128,.7)'>ظاهر</span>":"<button class='aact e' style='font-size:9px' data-rv-approve='"+rv.id+"'>موافقة</button>")
          +"<button class='aact' style='font-size:9px;color:rgba(192,132,252,.8)' data-rv-to-tm='"+rv.id+"'>شهادة</button>"
          +"<button class='aact d' style='font-size:9px' data-rv-del='"+rv.id+"'>حذف</button>"
          +"</div></div></div>";
      }).join("");
      c.querySelectorAll("[data-rv-approve]").forEach(function(btn){
        btn.addEventListener("click",function(){
          _api("/api/reviews",{method:"PATCH",body:JSON.stringify({id:+btn.getAttribute("data-rv-approve"),approved:true})})
            .then(function(){_loadReviews();_toast("تمت الموافقة");});
        });
      });
      c.querySelectorAll("[data-rv-to-tm]").forEach(function(btn){
        btn.addEventListener("click",function(){
          var rvId=+btn.getAttribute("data-rv-to-tm");
          var rv=list.find(function(x){return x.id===rvId;});
          if(!rv)return;
          _api("/api/testimonials",{method:"POST",body:JSON.stringify({name:rv.name,rating:rv.rating,body:rv.body,fromReview:true,reviewId:rv.id})})
            .then(function(){_loadTestimonials();_toast("تحويل لشهادة");}).catch(function(){_toast("خطأ");});
        });
      });
      c.querySelectorAll("[data-rv-del]").forEach(function(btn){
        btn.addEventListener("click",function(){
          if(!confirm("حذف؟"))return;
          _api("/api/reviews?id="+btn.getAttribute("data-rv-del"),{method:"DELETE"}).then(function(){_loadReviews();});
        });
      });
    }).catch(function(){});
  }
  // ══ REVIEWS (storefront) ═════════════════════════════════════════
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

  // ══ TESTIMONIALS (admin) ═════════════════════════════════════════
  function _loadTestimonials(){
    var c=document.getElementById("testimonials-c");if(!c)return;
    _api("/api/testimonials").then(function(r){return r.json();}).then(function(list){
      if(!list.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>لا توجد شهادات</div>";return;}
      c.innerHTML=list.map(function(t){
        var sh="";for(var i=1;i<=5;i++)sh+="<span style='color:"+(i<=(t.rating||5)?"rgba(251,191,36,.9)":"rgba(255,255,255,.15)")+";font-size:12px'>&#9733;</span>";
        return "<div class='rv-card'>"
          +"<div class='rv-card-stars'>"+sh+"</div>"
          +"<div class='rv-card-body'>"+_esc(t.body||"")+"</div>"
          +"<div style='display:flex;justify-content:space-between;align-items:center'>"
          +"<div class='rv-card-name'>"+_esc(t.name||"")+"</div>"
          +"<div style='display:flex;gap:5px'>"
          +(t.fromReview?"<span style='font-size:8px;color:rgba(168,85,247,.6)'>من تقييم</span>":"")
          +"<button class='aact d' style='font-size:9px' data-tm-del='"+t.id+"'>حذف</button>"
          +"</div></div></div>";
      }).join("");
      c.querySelectorAll("[data-tm-del]").forEach(function(btn){
        btn.addEventListener("click",function(){
          if(!confirm("حذف الشهادة؟"))return;
          _api("/api/testimonials?id="+btn.getAttribute("data-tm-del"),{method:"DELETE"}).then(function(){_loadTestimonials();});
        });
      });
      var sec=document.getElementById("testimonials-section");
      var sl=document.getElementById("testimonials-slider");
      if(sec&&sl&&list.length){
        sec.style.display="block";
        sl.innerHTML=list.slice(0,8).map(function(t){
          var sh2="";for(var i=1;i<=5;i++)sh2+="<span style='color:"+(i<=(t.rating||5)?"rgba(251,191,36,.9)":"rgba(255,255,255,.2)")+"'>&#9733;</span>";
          return "<div class='tm-slide'><div class='tm-stars'>"+sh2+"</div><div class='tm-body'>"+_esc(t.body||"")+"</div><div class='tm-name'>"+_esc(t.name||"")+"</div></div>";
        }).join("");
        if(sl._tmTimer)clearInterval(sl._tmTimer);
        var _tmI=0;var slides=sl.querySelectorAll(".tm-slide");
        if(slides.length>1){sl._tmTimer=setInterval(function(){_tmI=(_tmI+1)%slides.length;sl.scrollTo({left:_tmI*sl.offsetWidth,behavior:"smooth"});},3800);}
      }
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
        _toast("تمت الإضافة");
        ["tm-name","tm-body"].forEach(function(id){var e=document.getElementById(id);if(e)e.value="";});
        _loadTestimonials();
      }).catch(function(){_toast("خطأ");});
  }

  // ══ TESTIMONIALS (storefront) ════════════════════════════════════
  function _loadTestimonialsStorefront(){
    _api("/api/testimonials").then(function(r){return r.json();}).then(function(list){
      var sec=document.getElementById("testimonials-section");
      var sl=document.getElementById("testimonials-slider");
      if(!sec||!sl||!list.length)return;
      sec.style.display="block";
      sl.innerHTML=list.map(function(t){
        return "<div class='tcard'>"
          +(function(){
          var stars="";
          var r=t.rating||5;
          for(var i=0;i<r;i++)stars+="<span style='color:rgba(251,191,36,.85)'>&#9733;</span>";
          return "<div class='tcard-stars'>"+stars+"</div>";
        })()
          +"<div class='tcard-body'>"+_esc(t.body||"")+"</div>"
          +"<div class='tcard-name'>— "+_esc(t.name||"")+"</div>"
          +"</div>";
      }).join("");
    }).catch(function(){});
  }

  // ══ EXIT INTENT ══════════════════════════════════════════════════
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

  // ══ UPSELL ═══════════════════════════════════════════════════════
  var _upsellTimer=null;
  function _openProdById(id){
    try{
      var _pvk="wow_pv_"+id;
      var _pvc=parseInt(localStorage.getItem(_pvk)||"0")+1;
      localStorage.setItem(_pvk,_pvc);
      if(_pvc%3===0){_api("/api/analytics",{method:"POST",body:JSON.stringify({vid:window._vid||"?",source:"product",prodId:id,prodViews:_pvc})}).catch(function(){});}
    }catch(e){}
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

  // ══ SALES COUNTER ════════════════════════════════════════════════
  function _loadSalesCounter(){
    // Use KV-cached count to avoid admin auth requirement
    // Only show if admin token present (analytics needs auth)
    if(!_adminToken)return;
    _api("/api/analytics").then(function(r){return r.json();}).then(function(d){
      if(!d.confirmedOrders)return;
      var el=document.getElementById("sales-counter-bar");
      if(el)el.textContent=d.confirmedOrders+" طلبية مؤكدة هذا الشهر";
    }).catch(function(){});
  }

  // ══ STAR RATING INTERACTION ══════════════════════════════════════
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

  // ══ SETTINGS: About field ════════════════════════════════════════
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

    /* -- م29: QR SVG generator (local, no external API) -- */
  function _qrSvg(text){
    /* Reed-Solomon QR نبني نمط بديل بصري موثوق للروابط القصيرة
       باستخدام خوارزمية QR الحقيقية — نسخة مبسطة للنمط الصغير (21x21) */
    /* Encode chars as UTF-8 byte array */
    function toBytes(str){
      var r=[];
      for(let i=0;i<str.length;i++){
        var c=str.charCodeAt(i);
        if(c<128){r.push(c);}
        else if(c<2048){r.push(192|(c>>6));r.push(128|(c&63));}
        else{r.push(224|(c>>12));r.push(128|((c>>6)&63));r.push(128|(c&63));}
      }
      return r;
    }
    /* GF(256) arithmetic for Reed-Solomon */
    var EXP=new Array(512),LOG=new Array(256);
    (function(){var x=1;for(let i=0;i<255;i++){EXP[i]=x;LOG[x]=i;x<<=1;if(x>=256)x^=285;}
      for(let i=255;i<512;i++)EXP[i]=EXP[i-255];})();
    function gmul(a,b){if(a===0||b===0)return 0;return EXP[(LOG[a]+LOG[b])%255];}
    /* QR data encoding — byte mode */
    function encodeData(bytes){
      var bits=[];
      function pushBits(v,n){for(let i=n-1;i>=0;i--)bits.push((v>>i)&1);}
      pushBits(4,4);          // mode: byte
      pushBits(bytes.length,8); // char count
      for(let i=0;i<bytes.length;i++)pushBits(bytes[i],8);
      pushBits(0,4);          // terminator
      while(bits.length%8)bits.push(0);
      var pads=[236,17];var pi=0;
      while(bits.length<128){var p=pads[pi%2];pi++;for(var b=7;b>=0;b--)bits.push((p>>b)&1);}
      return bits;
    }
    /* Build codewords */
    function bitsToBytes(bits){
      var r=[];
      for(let i=0;i<bits.length;i+=8){var v=0;for(let j=0;j<8;j++)v=(v<<1)|(bits[i+j]||0);r.push(v);}
      return r;
    }
    /* RS error correction (7 EC codewords for version 1-M) */
    function rsEC(data,n){
      /* generator polynomial for n=7 */
      var gen=[0,87,229,146,149,238,102,21];
      var res=data.slice();
      for(let i=0;i<res.length;i++)for(let j=1;j<gen.length;j++)res[i+j]^=gmul(res[i],EXP[(LOG[EXP[gen[j]]]+i)%255]||EXP[gen[j]]);
      return res.slice(data.length);
    }
    var bytes=toBytes(text.slice(0,17)); /* version 1-M max 14 bytes; trim for safety */
    var dataBits=encodeData(bytes);
    var dataBytes=bitsToBytes(dataBits);
    var ecBytes=rsEC(dataBytes,7);
    var allBytes=dataBytes.concat(ecBytes);
    /* Convert to bit stream */
    var stream=[];
    for(let i=0;i<allBytes.length;i++)for(let b=7;b>=0;b--)stream.push((allBytes[i]>>b)&1);
    /* Version 1 QR: 21x21 — place bits using standard zigzag */
    var N=21;
    var mod=[];for(let r=0;r<N;r++){mod.push(new Array(N).fill(-1));}
    var func=[];for(let r=0;r<N;r++){func.push(new Array(N).fill(false));}
    /* Finder patterns */
    function finder(tr,tc){
      for(let r=-1;r<=7;r++)for(let c=-1;c<=7;c++){
        if(r<0||r>6||c<0||c>6)continue;
        var rv=tr+r,cv=tc+c;if(rv<0||rv>=N||cv<0||cv>=N)continue;
        var v=(r===0||r===6||c===0||c===6)?1:(r>=2&&r<=4&&c>=2&&c<=4?1:0);
        mod[rv][cv]=v;func[rv][cv]=true;
      }
      /* separators */
      for(let i=-1;i<=7;i++){
        if(tr+i>=0&&tr+i<N&&tc+7<N){if(!func[tr+i][tc+7]){mod[tr+i][tc+7]=0;func[tr+i][tc+7]=true;}}
        if(tr+7<N&&tc+i>=0&&tc+i<N){if(!func[tr+7][tc+i]){mod[tr+7][tc+i]=0;func[tr+7][tc+i]=true;}}
      }
    }
    finder(0,0);finder(0,14);finder(14,0);
    /* Timing patterns */
    for(let i=8;i<13;i++){mod[6][i]=i%2===0?1:0;func[6][i]=true;mod[i][6]=i%2===0?1:0;func[i][6]=true;}
    /* Dark module */
    mod[13][8]=1;func[13][8]=true;
    /* Format info (mask 0, error M) — precomputed */
    var fmt=[1,0,1,0,1,0,0,0,0,0,1,0,0,1,0];
    var fp=[[0,8],[1,8],[2,8],[3,8],[4,8],[5,8],[7,8],[8,8],[8,7],[8,5],[8,4],[8,3],[8,2],[8,1],[8,0]];
    var fp2=[[8,13],[8,14],[8,15],[8,16],[8,17],[8,18],[8,19],[8,20],[13,8],[14,8],[15,8],[16,8],[17,8],[18,8],[19,8]];
    for(let i=0;i<15;i++){mod[fp[i][0]][fp[i][1]]=fmt[i];func[fp[i][0]][fp[i][1]]=true;mod[fp2[i][0]][fp2[i][1]]=fmt[14-i];func[fp2[i][0]][fp2[i][1]]=true;}
    /* Place data bits — zigzag */
    var si=0;var up=true;
    for(var col=N-1;col>=1;col-=2){
      if(col===6)col--;
      for(var i2=0;i2<N;i2++){
        var r2=up?N-1-i2:i2;
        for(var dc=0;dc<2;dc++){
          var c2=col-dc;
          if(!func[r2][c2]){mod[r2][c2]=si<stream.length?stream[si++]:0;}
        }
      }
      up=!up;
    }
    /* Apply mask 0: (row+col)%2===0 */
    for(var r3=0;r3<N;r3++)for(var c3=0;c3<N;c3++){if(!func[r3][c3]&&(r3+c3)%2===0)mod[r3][c3]^=1;}
    /* Build SVG */
    var cell=8,quiet=3,sz=N*cell+quiet*2*cell;
    var rects="";
    for(var r4=0;r4<N;r4++)for(var c4=0;c4<N;c4++){
      if(mod[r4][c4]===1)rects+="<rect x='"+(c4*cell+quiet*cell)+"' y='"+(r4*cell+quiet*cell)+"' width='"+cell+"' height='"+cell+"' fill='#111'/>";
    }
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 '+sz+' '+sz+'" width="'+sz+'" height="'+sz+'">'
      +'<rect width="'+sz+'" height="'+sz+'" fill="white"/>'
      +rects+'</svg>';
  }

  function _showQR(prod){
    var origin=location.origin||window.location.origin||"";
    var link=origin+"/p/"+prod.id;
    var qrSvg=_qrSvg(link);
    var price=_effPrice(prod);
    var imgUrl=(prod.images&&prod.images[0])||"";
    var w=window.open("","_blank","width=400,height=580,scrollbars=no");
    if(!w){_toast(link);return;}
    w.document.write(
      '<!DOCTYPE html><html><head>'
      +'<meta charset="UTF-8">'
      +'<meta name="viewport" content="width=device-width,initial-scale=1">'
      +'<meta property="og:title" content="'+_esc(prod.name||"")+'">'
      +'<meta property="og:description" content="'+_esc((prod.desc||"").substring(0,120))+'">'
      +(imgUrl?'<meta property="og:image" content="'+_esc(imgUrl)+'">':'')
      +'<meta property="og:url" content="'+_esc(link)+'">'
      +'<meta property="og:type" content="product">'
      +'<meta name="twitter:card" content="summary_large_image">'
      +'<title>'+_esc(prod.name||"")+'</title>'
      +'<style>'
      +'*{margin:0;padding:0;box-sizing:border-box}'
      +'body{font-family:-apple-system,sans-serif;text-align:center;padding:24px 16px;background:#0a0016;color:#fff}'
      +'.brand{font-family:Georgia,serif;font-size:22px;font-weight:900;letter-spacing:5px;color:#c084fc;margin-bottom:4px}'
      +'.nm{font-size:14px;color:rgba(255,255,255,.7);margin-bottom:3px}'
      +'.price{font-family:Georgia,serif;font-size:17px;color:rgba(192,132,252,.9);margin-bottom:16px}'
      +'.qw{background:#fff;padding:12px;border-radius:12px;display:inline-block;margin-bottom:12px}'
      +'.lnk{font-size:9px;color:rgba(255,255,255,.3);word-break:break-all;margin-bottom:14px;padding:0 8px}'
      +'.btns{display:flex;gap:7px;justify-content:center;flex-wrap:wrap}'
      +'button{padding:8px 14px;border-radius:8px;border:none;cursor:pointer;font-size:11px}'
      +'.b1{background:#6d28d9;color:#fff}.b2{background:rgba(255,255,255,.08);color:rgba(255,255,255,.75)}'
      +'@media print{.btns,.lnk{display:none}body{background:#fff;padding:8px}}'
      +'</style></head><body>'
      +'<div class="brand">WOW</div>'
      +'<div class="nm">'+_esc(prod.name||"")+'</div>'
      +'<div class="price">'+_fmt(price)+' \u062f\u062c</div>'
      +'<div class="qw">'+qrSvg+'</div>'
      +'<div class="lnk">'+_esc(link)+'</div>'
      +'<div class="btns">'
      +'<button class="b1" id="cb">\u0646\u0633\u062e \u0627\u0644\u0631\u0627\u0628\u0637</button>'
      +'<button class="b2" onclick="window.print()">\u0637\u0628\u0627\u0639\u0629 QR</button>'
      +'<button class="b2" onclick="window.open(\\'https://wa.me/?text='+encodeURIComponent(prod.name+' '+link)+'\\')">\u0648\u0627\u062a\u0633\u0622\u0628</button>'
      +'</div>'
      +'<script>'
      +'document.getElementById("cb").addEventListener("click",function(){'
      +'  navigator.clipboard.writeText("'+_esc(link).replace(/"/g,'\\"')+'")'
      +'    .then(function(){document.getElementById("cb").textContent="\u062a\u0645 \u0627\u0644\u0646\u0633\u062e";}).catch(function(){});'
      +'});'
      +'<\\/script>'
      +'</body></html>'
    );
    w.document.close();
  }

  function _copyProdLink(prod){
    var link=location.origin+'/p/'+prod.id;
    navigator.clipboard.writeText(link)
      .then(function(){_toast('تم نسخ الرابط: /p/'+prod.id);})
      .catch(function(){_toast(link);});
  }

  // ══ STORIES (م48 - admin) ════════════════════════════════════════
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
          +"<button class='aact d' style='font-size:9px' data-del-story='"+s.id+"'>حذف</button>"
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
        _toast("تم نشر القصة!");
        ["st-title","st-body","st-img"].forEach(function(id){var e=document.getElementById(id);if(e)e.value="";});
        _loadStories();
      }).catch(function(){_toast("خطأ");});
  }

  // ══ DRAG AND DROP REORDER (م43) ══════════════════════════════════
  var _dragSrcRow=null;
  function _initDragReorder(container){
    var rows=container.querySelectorAll(".aprd-row[draggable]");
    rows.forEach(function(row){
      row.addEventListener("dragstart",function(e){_dragSrcRow=row;row.classList.add("dragging");e.dataTransfer.effectAllowed="move";});
      row.addEventListener("dragend",function(){row.classList.remove("dragging");container.querySelectorAll(".aprd-row").forEach(function(r){r.classList.remove("drag-over");});});
      row.addEventListener("dragover",function(e){e.preventDefault();e.dataTransfer.dropEffect="move";if(row!==_dragSrcRow)row.classList.add("drag-over");});
      row.addEventListener("dragleave",function(){row.classList.remove("drag-over");});
      row.addEventListener("drop",function(e){e.preventDefault();row.classList.remove("drag-over");if(_dragSrcRow&&_dragSrcRow!==row)_doReorder(container,_dragSrcRow,row);});
    });
    var _ts=null,_tp=null;
    rows.forEach(function(row){
      row.addEventListener("touchstart",function(e){
        if(e.touches.length!==1)return;
        _ts=row;row.classList.add("dragging");
        _tp=document.createElement("div");
        _tp.style.cssText="height:"+row.offsetHeight+"px;background:rgba(168,85,247,.06);border:1px dashed rgba(168,85,247,.25);border-radius:8px";
        row.parentNode.insertBefore(_tp,row.nextSibling);
      },{passive:true});
      row.addEventListener("touchmove",function(e){
        if(!_ts)return;
        var el=document.elementFromPoint(e.touches[0].clientX,e.touches[0].clientY);
        var tgt=el&&el.closest(".aprd-row");
        if(tgt&&tgt!==_ts){container.querySelectorAll(".aprd-row").forEach(function(r){r.classList.remove("drag-over");});tgt.classList.add("drag-over");}
      },{passive:true});
      row.addEventListener("touchend",function(e){
        if(!_ts)return;
        var el=document.elementFromPoint(e.changedTouches[0].clientX,e.changedTouches[0].clientY);
        var tgt=el&&el.closest(".aprd-row");
        _ts.classList.remove("dragging");
        container.querySelectorAll(".aprd-row").forEach(function(r){r.classList.remove("drag-over");});
        if(_tp)_tp.remove();
        if(tgt&&tgt!==_ts)_doReorder(container,_ts,tgt);
        _ts=null;_tp=null;
      });
    });
  }
  function _doReorder(container,src,target){
    var p=target.parentNode;
    var r2=Array.from(p.querySelectorAll(".aprd-row"));
    var si=r2.indexOf(src),ti=r2.indexOf(target);
    if(si>ti)p.insertBefore(src,target);else p.insertBefore(src,target.nextSibling);
    var newOrd=Array.from(p.querySelectorAll(".aprd-row")).map(function(r){return r.getAttribute("data-pid");}).filter(Boolean);
    _api("/api/products/reorder",{method:"POST",body:JSON.stringify({ids:newOrd})})
      .then(function(){_toast("تم حفظ الترتيب");}).catch(function(){_toast("خطأ");});
  }
  // ══ KEYBOARD SHORTCUTS (م46) ══════════════════════════════════════
  var _kbHintTimer=null;
  function _initKeyboardShortcuts(){
    document.addEventListener("keydown",function(e){
      var adm=document.getElementById("adm");
      var admOpen=adm&&adm.classList.contains("on");
      /* F11 works always */
      if(e.key==="F11"){e.preventDefault();_toggleFullscreen();return;}
      if(!admOpen)return;
      /* ? or / : show hint */
      if((e.key==="?"||e.key==="/")&&!e.ctrlKey&&!e.metaKey){_showKbHint();return;}
      /* Escape: close open modal or admin */
      if(e.key==="Escape"&&!e.ctrlKey){
        var openMods=document.querySelectorAll(".mod-ov");
        var closed=false;
        openMods.forEach(function(m){if(m.style.display!=="none"&&m.style.display!==""){m.style.display="none";closed=true;}});
        if(!closed)_closeAdm();
        return;
      }
      if(e.ctrlKey||e.metaKey){
        var k=e.key.toLowerCase();
        if(k==="n"){e.preventDefault();_aTab("addprod",null);_showKbHint();return;}
        if(k==="o"){e.preventDefault();_aTab("orders",null);_loadOrders();_showKbHint();return;}
        if(k==="f"){e.preventDefault();
          _aTab("orders",null);
          setTimeout(function(){
            var si=document.getElementById("ord-f-q");if(si){si.focus();si.select();}
          },120);
          return;
        }
        if(k==="s"){e.preventDefault();
          var curTab=adm.getAttribute("data-cur-tab")||"";// save settings only if in settings
          _saveSettingsFull();_showKbHint();
          return;
        }
        if(k==="p"){e.preventDefault();
          /* Ctrl+P: طباعة الطلبيات المحددة أو فتح نافذة الطباعة */
          var pbtn=document.getElementById("bulk-print-btn");
          if(pbtn&&!pbtn.disabled){pbtn.click();}
          else{window.print();}
          return;
        }
        if(k==="a"){e.preventDefault();_aTab("analytics",null);_loadAnalytics();_showKbHint();return;}
        if(k==="l"){e.preventDefault();
          /* Ctrl+L: تبديل Fullscreen */
          _toggleFullscreen();
          return;
        }
        if(k==="d"){e.preventDefault();_aTab("orders",null);_groupOrders();return;}
      }
      /* أرقام 1-9: تبديل سريع بين التبويبات */
      if(!e.ctrlKey&&!e.metaKey&&!e.altKey&&!e.shiftKey){
        var tabs=["analytics","orders","products","addprod","coupons","archive","settings","activity","stock"];
        var n=parseInt(e.key);
        if(n>=1&&n<=9&&tabs[n-1]){
          var activeEl=document.activeElement;
          if(activeEl&&(activeEl.tagName==="INPUT"||activeEl.tagName==="TEXTAREA"||activeEl.tagName==="SELECT"))return;
          e.preventDefault();
          _aTab(tabs[n-1],null);
          _showKbHint();
        }
      }
    });
  }
  function _showKbHint(){
    var hint=document.getElementById("kb-hint");if(!hint)return;
    hint.style.display="block";hint.style.opacity="1";
    clearTimeout(_kbHintTimer);
    _kbHintTimer=setTimeout(function(){
      hint.style.opacity="0";
      setTimeout(function(){hint.style.display="none";hint.style.opacity="1";},280);
    },3500);
  }

  // ══ FULLSCREEN (م47) ══════════════════════════════════════════════
  function _toggleFullscreen(){
    function _fsIcon(on){
      var btns=[document.getElementById("fs-btn"),document.querySelector("button[onclick*=\'_toggleFullscreen\']")];
      btns.forEach(function(b){if(b)b.textContent=on?"▥":"▣";});
    }
    try{
      var el=document.documentElement;
      if(!document.fullscreenElement&&!document.webkitFullscreenElement){
        var req=el.requestFullscreen||el.webkitRequestFullscreen||el.mozRequestFullScreen||el.msRequestFullscreen;
        if(req){req.call(el);}
        try{localStorage.setItem("wow_fullscreen","1");}catch(e){}
        _fsIcon(true);
      } else {
        var ex=document.exitFullscreen||document.webkitExitFullscreen||document.mozCancelFullScreen||document.msExitFullscreen;
        if(ex){ex.call(document);}
        try{localStorage.removeItem("wow_fullscreen");}catch(e){}
        _fsIcon(false);
      }
    }catch(err){}
  }
  function _initFullscreen(){
    /* استعادة حالة ملء الشاشة من الجلسة السابقة */
    try{
      if(localStorage.getItem("wow_fullscreen")==="1"){
        var el=document.documentElement;
        var req=el.requestFullscreen||el.webkitRequestFullscreen||el.mozRequestFullScreen;
        if(req)req.call(el).catch(function(){});
      }
    }catch(e){}
    /* تحديث الأيقونة عند تغيير حالة ملء الشاشة */
    function _onFsChange(){
      var on=!!(document.fullscreenElement||document.webkitFullscreenElement);
      var btns=[document.getElementById("fs-btn"),document.querySelector("button[title='F11']")];
      btns.forEach(function(b){if(b)b.textContent=on?"▥":"▣";});
      try{if(on)localStorage.setItem("wow_fullscreen","1");else localStorage.removeItem("wow_fullscreen");}catch(e){}
    }
    document.addEventListener("fullscreenchange",_onFsChange);
    document.addEventListener("webkitfullscreenchange",_onFsChange);
  }

  // ══ MULTI-LANGUAGE (م44) ══════════════════════════════════════════
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
    document.documentElement.lang=_lang;
    document.documentElement.dir=_lang==="ar"?"rtl":"ltr";
    var isAr=_lang==="ar";
    var pm={"search-inp":isAr?"ابحث عن منتج...":"Search...","o-name":isAr?"الاسم الكامل":"Full Name","o-p1":isAr?"رقم الهاتف":"Phone","o-coupon":isAr?"كود الخصم":"Coupon"};
    Object.keys(pm).forEach(function(id){var el=document.getElementById(id);if(el)el.placeholder=pm[id];});
    var sb=document.getElementById("cart-sb");if(sb)sb.setAttribute("dir",isAr?"rtl":"ltr");
  }
  function _initLang(){
    try{var saved=localStorage.getItem("wow_lang");if(saved)_setLang(saved);}catch{}
  }

  // ══ SETTINGS SAVE ENHANCEMENT (م38,م39,م40,م44) ══════════════════
  var _origSaveSettings=null;

  // ══ TRUST BADGES storefront (م40) ════════════════════════════════
  function _renderTrustBadges(settings){
    var badges=settings.trustBadges||{};
    var badgeBar=document.getElementById("trust-badges-bar");
    if(!badgeBar)return;
    var items=[];
    if(badges.ssl)items.push("SSL آمن");
    if(badges.cod)items.push("الدفع عند الاستلام");
    if(badges.ret)items.push("إرجاع مجاني");
    if(badges.quality)items.push("جودة مضمونة");
    if(badges.fast)items.push("شحن سريع");
    if(items.length){
      badgeBar.innerHTML=items.map(function(b){return "<div class='trust-badge'>"+b+"</div>";}).join("");
      badgeBar.style.display="flex";
    }
  }

  // ══ FAQ Modal (م39) ══════════════════════════════════════════════
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
      _genericModal("الأسئلة الشائعة",body);
    }).catch(function(){});
  }
  function _showRefundPolicy(){
    _api("/api/settings").then(function(r){return r.json();}).then(function(s){
      var pol=s.refundPolicy||s.refund||"";
      var body="<div style='font-size:12px;color:var(--dim);line-height:1.8;padding:6px'>"+_esc(pol||"لا توجد سياسة إرجاع محددة بعد.").replace(/\\n/g,"<br>")+"</div>";
      _genericModal("سياسة الإرجاع",body);
    }).catch(function(){});
  }
  function _genericModal(title,body){
    var mo=document.createElement("div");mo.className="mod-ov";mo.style.zIndex="1100";
    mo.innerHTML="<div class='mod'><div class='mod-title'>"+title
      +"<button class='xbtn' data-generic-close='1'>✕</button></div>"+body+"</div>";
    var closeBtn=mo.querySelector("[data-generic-close]");
    if(closeBtn)closeBtn.addEventListener("click",function(){mo.remove();});
    document.body.appendChild(mo);mo.style.display="flex";
  }

  // ══ PRODUCT FORM: save variants/schedule/alert ════════════════════
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

  // ══ SETTINGS SAVE with all new fields ════════════════════════════
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
    var ssc=document.getElementById("s-ship-cost");
    var body={
      storeName:sn?sn.value:"",whatsapp:sw?sw.value:"",email:se?se.value:"",
      instagram:si?si.value:"",hero_background:sh?sh.value:"",
      admin_discount:sd?parseFloat(sd.value)||0:0,
      defaultShippingCost:ssc?parseFloat(ssc.value)||0:0,
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
      _toast("تم الحفظ");
      if(btn){btn.textContent="Save Settings";btn.disabled=false;}
      if(body.lang)_setLang(body.lang);
    }).catch(function(){_toast("خطأ");if(btn){btn.textContent="Save Settings";btn.disabled=false;}});
  }

  // ══ LOAD SETTINGS enhanced ════════════════════════════════════════
  function _loadSettingsExtra(s){
    var sfaq=document.getElementById("s-faq");if(sfaq&&s.faq)sfaq.value=s.faq;
    var sref=document.getElementById("s-refund");if(sref&&s.refundPolicy)sref.value=s.refundPolicy;
    var slang=document.getElementById("s-lang");if(slang&&s.lang)slang.value=s.lang;
    var ssc=document.getElementById("s-ship-cost");if(ssc&&s.defaultShippingCost)ssc.value=s.defaultShippingCost;
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


  document.addEventListener("DOMContentLoaded",function(){
    try{
      // ── مض17: HEATMAP ──
      (function(){
        var _clicks=[];var _hmActive=false;var _hmOverlay=null;
        document.addEventListener("click",function(e){
          if(_hmActive)return;
          var x=Math.round((e.clientX/window.innerWidth)*100);
          var y=Math.round((e.pageY/document.body.scrollHeight)*100);
          _clicks.push({x:x,y:y});
          if(_clicks.length>=10){
            try{_api("/api/analytics",{method:"POST",body:JSON.stringify({vid:window._vid||"?",source:"heatmap",clicks:_clicks.slice()})}).catch(function(){});}catch(e2){}
            _clicks=[];
          }
        },{passive:true});
        window._showHeatmap=function(){
          if(_hmOverlay){_hmOverlay.remove();_hmOverlay=null;_hmActive=false;return;}
          if(!_clicks.length){alert("لا بيانات نقر بعد");return;}
          _hmActive=true;
          _hmOverlay=document.createElement("div");
          _hmOverlay.style.cssText="position:fixed;inset:0;pointer-events:none;z-index:9990;";
          var W=window.innerWidth,H=window.innerHeight;
          var svg="<svg xmlns='http://www.w3.org/2000/svg' width='"+W+"' height='"+H+"' style='position:absolute;inset:0'>";
          _clicks.forEach(function(c){
            var cx=Math.round(c.x/100*W),cy=Math.round(c.y/100*H);
            svg+="<circle cx='"+cx+"' cy='"+cy+"' r='18' fill='rgba(239,68,68,.18)' stroke='rgba(239,68,68,.4)' stroke-width='1'/>";
            svg+="<circle cx='"+cx+"' cy='"+cy+"' r='5' fill='rgba(239,68,68,.5)'/>";
          });
          svg+="</svg>";
          _hmOverlay.innerHTML=svg;
          var cb=document.createElement("button");
          cb.style.cssText="position:fixed;top:10px;left:10px;z-index:9991;background:rgba(0,0,0,.85);color:#fff;border:1px solid rgba(239,68,68,.4);border-radius:7px;padding:6px 12px;cursor:pointer;font-size:11px;pointer-events:all";
          cb.textContent="إغلاق ("+_clicks.length+" نقرة)";
          cb.onclick=function(){_hmOverlay.remove();_hmOverlay=null;_hmActive=false;};
          _hmOverlay.appendChild(cb);
          document.body.appendChild(_hmOverlay);
        };
      })();

      // ── HEADER SCROLL GLOW ──
      (function(){
        var h=document.querySelector(".hdr");if(!h)return;
        window.addEventListener("scroll",function(){
          h.classList.toggle("scrolled",window.scrollY>44);
        },{passive:true});
      })();

      // ── HEADER BUTTONS (touch-optimised) ──
      _fastTap(document.getElementById("cart-btn-hdr"),function(e){e.preventDefault();_openCart();});
      _fastTap(document.getElementById("adm-btn-hdr"),function(e){e.preventDefault();_openAdminLogin();});

      // ── CART CLOSE (touch-optimised) ──
      _fastTap(document.getElementById("cart-xbtn"),_closeCart);
      _fastTap(document.getElementById("ov"),_closeCart);

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
        _fastTap(el,function(){pillMap[id](el);});
      });

      // ── BOTTOM NAV (touch-optimised via _fastTap) ──
      var bnHome=document.getElementById("bn-home");
      _fastTap(bnHome,function(){window.scrollTo({top:0,behavior:"smooth"});});
      var bnCart=document.getElementById("bn-cart");
      _fastTap(bnCart,_openCart);
      var bnTrack=document.getElementById("bn-track");
      _fastTap(bnTrack,function(){_openMod("track-mod");});
      var bnHelp=document.getElementById("bn-help");
      _fastTap(bnHelp,function(){_openMod("faq-mod");});

      // ── FOOTER LINKS ──
      var flTrack=document.getElementById("fl-track");if(flTrack)flTrack.addEventListener("click",function(){_openMod("track-mod");});
      var flFaq=document.getElementById("fl-faq");if(flFaq)flFaq.addEventListener("click",function(){_openMod("faq-mod");});
      var flPolicy=document.getElementById("fl-policy");if(flPolicy)flPolicy.addEventListener("click",function(){_openMod("policy-mod");});

      // ── MODAL CLOSE BUTTONS (touch-optimised) ──
      var modalClosePairs=[
        ["login-xbtn","login-mod"],
        ["size-xbtn","size-mod"],
        ["prod-xbtn","prod-mod"],
        ["checkout-xbtn","checkout-mod"],
        ["inv-xbtn","inv-mod"],
        ["track-xbtn","track-mod"],
        ["faq-xbtn","faq-mod"],
        ["policy-xbtn","policy-mod"],
        ["review-xbtn","review-mod"]
      ];
      modalClosePairs.forEach(function(pair){
        _fastTap(document.getElementById(pair[0]),function(){_closeMod(pair[1]);});
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
      var pcostEl=document.getElementById("p-cost");if(pcostEl){pcostEl.addEventListener("input",_updateMarginPreview);}

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
    _openProdById:_openProdById,
    _showCsvCols:_showCsvCols,
    _restoreSelectedArchive:_restoreSelectedArchive
  };
})();
</script>
</body>
</html>`;
}
