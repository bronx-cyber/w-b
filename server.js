/* ============================================================
   BRONX ULTRA v5.5 · ADVANCED OSINT PANEL
   Google Login + Gmail/Password · Token System · Admin · Broadcast
   @BRONX_ULTRA · Render.com Ready
   ============================================================ */
const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

/* ============================================================
   CONFIG
   ============================================================ */
const CFG = {
  BASE:         process.env.BRONX_API_BASE || 'https://bronx-papa-27y2.onrender.com',
  KEY:          process.env.BRONX_API_KEY  || 'web-api-99',
  ADMIN_U:      (process.env.ADMIN_USER    || 'bronx').toLowerCase(),
  ADMIN_P:      process.env.ADMIN_PASS     || 'bronx9@2025',
  UPI_ID:       process.env.UPI_ID         || 'bronxultra850956@upi',
  UPI_NAME:     process.env.UPI_NAME       || 'BRONX ULTRA',
  TG_LINK:      process.env.TG_LINK        || 'https://t.me/BRONX_ULTRA',
  QR_IMG:       process.env.QR_IMG         || 'https://i.ibb.co/dHfR9KD/qr.png',
  GOOGLE_CID:   process.env.GOOGLE_CLIENT_ID || '',
  PORT:         process.env.PORT           || 3000,
  COOKIE:       'bx_sess',
  KV_URL:       process.env.UPSTASH_REDIS_REST_URL   || process.env.KV_REST_API_URL   || '',
  KV_TOKEN:     process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN || ''
};

const googleClient = new OAuth2Client(CFG.GOOGLE_CID);

/* ============================================================
   STORAGE (Upstash REST or in-memory)
   ============================================================ */
const MEM = new Map();
async function kvGet(k){
  if (CFG.KV_URL && CFG.KV_TOKEN){
    try{
      const r = await fetch(CFG.KV_URL + '/get/' + encodeURIComponent(k), { headers:{ Authorization:'Bearer '+CFG.KV_TOKEN }});
      const j = await r.json();
      return j && j.result ? JSON.parse(j.result) : null;
    }catch(e){ return null; }
  }
  const v = MEM.get(k); return v ? JSON.parse(v) : null;
}
async function kvSet(k, v, ttl){
  const s = JSON.stringify(v);
  if (CFG.KV_URL && CFG.KV_TOKEN){
    let u = CFG.KV_URL + '/set/' + encodeURIComponent(k);
    if (ttl) u += '?EX=' + ttl;
    try{ await fetch(u, { method:'POST', headers:{ Authorization:'Bearer '+CFG.KV_TOKEN }, body:s }); }catch(e){}
  } else MEM.set(k, s);
}
async function kvDel(k){
  if (CFG.KV_URL && CFG.KV_TOKEN){
    try{ await fetch(CFG.KV_URL + '/del/' + encodeURIComponent(k), { method:'POST', headers:{ Authorization:'Bearer '+CFG.KV_TOKEN }}); }catch(e){}
  } else MEM.delete(k);
}
async function kvKeys(p){
  if (CFG.KV_URL && CFG.KV_TOKEN){
    try{
      const r = await fetch(CFG.KV_URL + '/keys/' + encodeURIComponent(p) + '*', { headers:{ Authorization:'Bearer '+CFG.KV_TOKEN }});
      const j = await r.json();
      return (j && j.result) || [];
    }catch(e){ return []; }
  }
  return Array.from(MEM.keys()).filter(k => k.startsWith(p));
}

/* ============================================================
   HELPERS
   ============================================================ */
function esc(s){
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function hashPass(p){
  const s = crypto.randomBytes(16).toString('hex');
  return s + ':' + crypto.scryptSync(p, s, 64).toString('hex');
}
function verifyPass(p, stored){
  try{
    const parts = String(stored).split(':');
    if (parts.length !== 2) return false;
    const c = crypto.scryptSync(p, parts[0], 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(parts[1],'hex'), Buffer.from(c,'hex'));
  }catch(e){ return false; }
}
function setCookie(res, name, val, maxAge){
  res.cookie(name, val, { httpOnly:true, sameSite:'lax', maxAge: maxAge*1000 });
}
function clearCookie(res, name){ res.clearCookie(name); }
function randToken(){ return 'BRONX-' + crypto.randomBytes(8).toString('hex').toUpperCase(); }
function randOrderId(){ return 'BXO' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).slice(2,5).toUpperCase(); }
function clientIP(req){
  const f = req.headers['x-forwarded-for'];
  if (f) return String(f).split(',')[0].trim();
  return req.ip || req.connection.remoteAddress || 'unknown';
}
function deviceName(ua){
  ua = String(ua||'');
  let os = 'Unknown';
  if (/Windows/i.test(ua)) os = 'Windows';
  else if (/Android/i.test(ua)) os = 'Android';
  else if (/iPhone|iPad/i.test(ua)) os = 'iOS';
  else if (/Mac/i.test(ua)) os = 'macOS';
  else if (/Linux/i.test(ua)) os = 'Linux';
  let br = 'Browser';
  if (/Edg/i.test(ua)) br = 'Edge';
  else if (/Chrome/i.test(ua)) br = 'Chrome';
  else if (/Firefox/i.test(ua)) br = 'Firefox';
  else if (/Safari/i.test(ua)) br = 'Safari';
  return br + ' · ' + os;
}
function emailToUid(email){
  return 'u_' + crypto.createHash('sha256').update(String(email).toLowerCase()).digest('hex').slice(0, 24);
}
function isGmail(email){
  return /^[a-zA-Z0-9._%+-]+@gmail\.com$/i.test(String(email||''));
}

/* ============================================================
   SESSIONS
   ============================================================ */
async function getSession(req){
  const t = req.cookies[CFG.COOKIE];
  if (!t) return null;
  const s = await kvGet('sess:' + t);
  if (!s) return null;
  if (s.exp && Date.now() > s.exp){ await kvDel('sess:' + t); return null; }
  if (s.role === 'user'){
    const u = await kvGet('user:' + s.uid);
    if (!u){ await kvDel('sess:' + t); return null; }
    if (u.banned){ await kvDel('sess:' + t); return null; }
  }
  return Object.assign({ token:t }, s);
}
async function createSession(user, role, extra, ttl){
  const t = crypto.randomBytes(32).toString('hex');
  await kvSet('sess:' + t, Object.assign({ user, role, exp: Date.now() + ttl*1000 }, extra||{}), ttl);
  return t;
}

/* ============================================================
   DEFAULT FEATURES + PLANS
   ============================================================ */
const DEFAULT_FEATURES = [
  { id:'numinfo',  name:'Number Info',      emoji:'📱', color:'#22d3ee', hint:'10 DIGIT NUMBER', placeholder:'9876543210',        endpoint:'/api/key-bronx/number',  param:'num',     type:'number' },
  { id:'numleak',  name:'Advance Num Info', emoji:'🕵️', color:'#a855f7', hint:'10 DIGIT NUMBER', placeholder:'9876543210',        endpoint:'/api/key-bronx/numleak', param:'num',     type:'number' },
  { id:'aadhar',   name:'Aadhar Info',      emoji:'🪪', color:'#22c55e', hint:'12 DIGIT AADHAR', placeholder:'393933081942',      endpoint:'/api/key-bronx/aadhar',  param:'num',     type:'number', len:12 },
  { id:'veh2num',  name:'Vehicle → Mobile', emoji:'🚗', color:'#f97316', hint:'VEHICLE NUMBER',  placeholder:'KL41V3504',         endpoint:'/api/key-bronx/veh2num', param:'vehicle', type:'text',   upper:true },
  { id:'upi',      name:'UPI Info',         emoji:'💳', color:'#22c55e', hint:'UPI ID',          placeholder:'example@ybl',       endpoint:'/api/key-bronx/upi',     param:'upi',     type:'text' },
  { id:'ifsc',     name:'IFSC Info',        emoji:'🏦', color:'#eab308', hint:'11 CHAR IFSC',    placeholder:'SBIN0001234',       endpoint:'/api/key-bronx/ifsc',    param:'ifsc',    type:'text',   upper:true, len:11 },
  { id:'pincode',  name:'Pincode Info',     emoji:'📍', color:'#38bdf8', hint:'6 DIGIT PINCODE', placeholder:'110001',            endpoint:'/api/key-bronx/pincode', param:'pin',     type:'number', len:6 },
  { id:'ip',       name:'IP Info',          emoji:'🌐', color:'#2aabee', hint:'IP ADDRESS',      placeholder:'8.8.8.8',           endpoint:'/api/key-bronx/ip',      param:'ip',      type:'text' },
  { id:'ff',       name:'Free Fire Info',   emoji:'🎮', color:'#f97316', hint:'FREE FIRE UID',   placeholder:'123456789',         endpoint:'/api/key-bronx/ff',      param:'uid',     type:'text' },
  { id:'mail',     name:'Mail Info',        emoji:'📧', color:'#ec4899', hint:'EMAIL ADDRESS',   placeholder:'example@gmail.com', endpoint:'/api/custom/mail',       param:'num',     type:'text' },
  { id:'tginfo',   name:'Telegram Lookup',  emoji:'✈️', color:'#2aabee', hint:'USERNAME or ID',  placeholder:'@JAUUOWNER',        endpoint:'/api/custom/user',       param:'num',     type:'text' }
];

const DEFAULT_PLANS = [
  { id:'p1d',  label:"1 Day's",  days:1,  price:20,    tag:'Testing plan 🥳',        popular:false },
  { id:'p5d',  label:"5 Day's",  days:5,  price:70,    tag:'Noob plan',              popular:false },
  { id:'p10d', label:"10 Day's", days:10, price:100,   tag:'Silver plan',            popular:false },
  { id:'p30d', label:"30 Day's", days:30, price:500,   tag:'Recommended Pro Plan ❤️', popular:true },
  { id:'p60d', label:"60 Day's", days:60, price:1000,  tag:'Vip Plan',               popular:false },
  { id:'p90d', label:"90 Day's", days:90, price:1500,  tag:'Ultra VIP Plan',         popular:false }
];

async function getFeatures(){
  const f = await kvGet('config:features');
  if (f && Array.isArray(f)) return f;
  await kvSet('config:features', DEFAULT_FEATURES);
  return DEFAULT_FEATURES;
}
async function getPlans(){
  const p = await kvGet('config:plans');
  if (p && Array.isArray(p)) return p;
  await kvSet('config:plans', DEFAULT_PLANS);
  return DEFAULT_PLANS;
}
async function adminCreds(){
  const c = await kvGet('admin:creds');
  if (c) return c;
  return { u: CFG.ADMIN_U, p: hashPass(CFG.ADMIN_P) };
}

/* ============================================================
   COMMON CSS
   ============================================================ */
const CSS = `
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#05070c;color:#fff;min-height:100vh;overflow-x:hidden;position:relative}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(ellipse at 20% 20%,rgba(239,43,58,.2),transparent 55%),radial-gradient(ellipse at 80% 80%,rgba(34,211,238,.14),transparent 60%)}
body::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;background:linear-gradient(rgba(239,43,58,.05) 1px,transparent 1px) 0 0/100% 120px,linear-gradient(90deg,rgba(239,43,58,.03) 1px,transparent 1px) 0 0/120px 100%;-webkit-mask-image:radial-gradient(ellipse at center,#000 20%,transparent 75%);mask-image:radial-gradient(ellipse at center,#000 20%,transparent 75%)}
.wrap{position:relative;z-index:1}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:12px 20px;font-size:12px;letter-spacing:.2em;font-weight:800;border-radius:8px;cursor:pointer;font-family:inherit;text-decoration:none;border:1px solid #22d3ee;color:#22d3ee;background:rgba(34,211,238,.08);transition:.2s}
.btn:hover{background:rgba(34,211,238,.2);box-shadow:0 0 25px rgba(34,211,238,.4)}
.btn.red{border-color:#ef2b3a;color:#ef2b3a;background:rgba(239,43,58,.08)}
.btn.red:hover{background:rgba(239,43,58,.2)}
.btn.gr{border-color:#22c55e;color:#22c55e;background:rgba(34,197,94,.08)}
.btn.gr:hover{background:rgba(34,197,94,.2)}
.btn.gd{border-color:#eab308;color:#eab308;background:rgba(234,179,8,.08)}
.btn.gd:hover{background:rgba(234,179,8,.2)}
.btn:disabled{opacity:.4;cursor:not-allowed}
.chip{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;font-size:11px;letter-spacing:.15em;font-weight:700;color:#22d3ee;border:1px solid rgba(34,211,238,.55);background:rgba(34,211,238,.06);border-radius:6px;cursor:pointer;text-decoration:none;transition:.2s;font-family:inherit}
.chip:hover{background:rgba(34,211,238,.15)}
.chip.red{color:#ef2b3a;border-color:rgba(239,43,58,.55);background:rgba(239,43,58,.08)}
.chip.gd{color:#eab308;border-color:rgba(234,179,8,.55);background:rgba(234,179,8,.08)}
.chip.gd:hover{background:rgba(234,179,8,.2)}
.dot{width:8px;height:8px;border-radius:999px;background:#ef2b3a;box-shadow:0 0 10px #ef2b3a;display:inline-block}
.dot.green{background:#22c55e;box-shadow:0 0 10px #22c55e}
.dot.gd{background:#eab308;box-shadow:0 0 10px #eab308}
input,select,textarea{width:100%;padding:12px 14px;font-size:14px;background:rgba(0,0,0,.5);border:1px solid rgba(255,255,255,.15);border-radius:8px;color:#fff;outline:none;font-family:inherit}
input:focus,select:focus,textarea:focus{border-color:#22d3ee;box-shadow:0 0 0 2px rgba(34,211,238,.15)}
label{display:block;text-align:left;font-size:10px;letter-spacing:.25em;color:#94a3b8;margin-bottom:6px;font-weight:700;margin-top:12px}
.err{margin-top:14px;padding:10px;border-radius:8px;font-size:12px;color:#ff6b8a;background:rgba(255,46,99,.08);border:1px solid rgba(255,46,99,.35);display:none}
.err.show{display:block}
.ok{margin-top:14px;padding:10px;border-radius:8px;font-size:12px;color:#86efac;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.35);display:none}
.ok.show{display:block}
.center{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;position:relative;z-index:1}
.box{width:100%;max-width:440px;padding:36px 28px;border-radius:18px;background:linear-gradient(180deg,rgba(0,0,0,.75),rgba(0,0,0,.9));border:1px solid rgba(239,43,58,.5);box-shadow:0 0 60px rgba(239,43,58,.35);text-align:center}
.logo{width:72px;height:72px;margin:0 auto 18px;display:grid;place-items:center;font-size:34px;background:linear-gradient(135deg,rgba(239,43,58,.7),#000);border:1px solid rgba(239,43,58,.9);clip-path:polygon(50% 0,100% 25%,100% 75%,50% 100%,0 75%,0 25%);box-shadow:0 0 30px rgba(239,43,58,.6)}
h1{font-size:26px;letter-spacing:.2em;font-weight:900;margin-bottom:6px}
h1 span{color:#ef2b3a}
.sub{color:#22d3ee;font-size:11px;letter-spacing:.4em;margin-bottom:24px}
.broadcast{position:fixed;top:0;left:0;right:0;z-index:200;padding:12px 20px;background:linear-gradient(90deg,rgba(239,43,58,.95),rgba(234,179,8,.95));color:#fff;font-weight:700;font-size:13px;letter-spacing:.05em;text-align:center;box-shadow:0 4px 20px rgba(239,43,58,.5)}
.tabs{display:flex;gap:6px;margin-bottom:16px}
.tab{flex:1;padding:12px;text-align:center;font-size:11px;letter-spacing:.2em;font-weight:800;border-radius:8px;cursor:pointer;background:rgba(0,0,0,.4);border:1px solid rgba(255,255,255,.1);color:#94a3b8;font-family:inherit;transition:.2s}
.tab.on{background:rgba(34,211,238,.12);border-color:#22d3ee;color:#22d3ee;box-shadow:0 0 20px rgba(34,211,238,.25)}
.gbox{margin-top:8px;display:flex;flex-direction:column;gap:12px}
.gbtn{display:flex;align-items:center;justify-content:center;gap:12px;padding:14px;border-radius:10px;background:#fff;color:#1a1a1a;font-size:14px;font-weight:600;cursor:pointer;border:0;font-family:inherit;letter-spacing:0;transition:.2s}
.gbtn:hover{background:#f1f1f1;transform:translateY(-1px);box-shadow:0 6px 20px rgba(255,255,255,.15)}
.gbtn svg{width:20px;height:20px}
.or{display:flex;align-items:center;gap:12px;color:#64748b;font-size:10px;letter-spacing:.3em;margin:18px 0}
.or::before,.or::after{content:"";flex:1;height:1px;background:rgba(255,255,255,.1)}
.admin-toggle{margin-top:22px;font-size:10px;letter-spacing:.2em;color:#64748b;background:none;border:0;cursor:pointer;font-family:inherit;text-decoration:underline}
.admin-form{margin-top:14px;display:none;text-align:left}
.admin-form.show{display:block}
.info{font-size:11px;color:#94a3b8;line-height:1.6;margin-top:12px;padding:10px;border-radius:8px;background:rgba(34,211,238,.04);border:1px solid rgba(34,211,238,.25)}
`;

const BROADCAST_JS = `
async function loadBroadcast(){
  try{
    var r = await fetch('/api/broadcast');
    var j = await r.json();
    if (j && j.active && j.message){
      var d = document.createElement('div');
      d.className = 'broadcast';
      d.innerHTML = '📢 ' + j.message.replace(/</g,'&lt;');
      document.body.appendChild(d);
    }
  }catch(e){}
}
`;

/* ============================================================
   HTML · LOGIN (Google Sign-In + Gmail/Password)
   ============================================================ */
const LOGIN_HTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>BRONX ULTRA · Sign In</title>
<script src="https://accounts.google.com/gsi/client" async defer></script>
<style>
${CSS}
</style></head><body>
<div class="center">
  <div class="box">
    <div class="logo">🕵️</div>
    <h1><span>BRONX</span> ULTRA</h1>
    <div class="sub">@BRONX_ULTRA · SIGN IN</div>

    <div class="tabs">
      <button class="tab on" id="tabG" onclick="sw('g')">GOOGLE</button>
      <button class="tab" id="tabM" onclick="sw('m')">GMAIL + PASS</button>
    </div>

    <!-- GOOGLE PANE -->
    <div id="paneG">
      <div class="gbox">
        <div id="g_id_onload" data-client_id="${esc(CFG.GOOGLE_CID)}" data-callback="handleGoogle" data-auto_prompt="false"></div>
        <div class="g_id_signin" data-type="standard" data-size="large" data-theme="filled_black" data-text="signin_with" data-shape="rectangular" data-logo_alignment="left" data-width="320"></div>
      </div>
      <div class="info">🔒 Sirf <b style="color:#22d3ee">@gmail.com</b> allowed. Ek click me login.</div>
    </div>

    <!-- GMAIL + PASS PANE -->
    <div id="paneM" style="display:none">
      <label>GMAIL (@gmail.com) *</label>
      <input id="mu" type="email" placeholder="example@gmail.com" autocomplete="email"/>
      <label>PASSWORD *</label>
      <input id="mp" type="password" placeholder="Enter password" autocomplete="current-password"/>
      <button class="btn gr" style="width:100%;margin-top:16px;padding:14px" onclick="gmailLogin()">🔐 SIGN IN</button>
      <div class="info" style="margin-top:12px">Pehli baar? <a href="javascript:sw('r')" style="color:#22d3ee;font-weight:700;text-decoration:underline">Register here</a> — Gmail + password se account banao. Data permanently safe rahega.</div>
    </div>

    <!-- REGISTER PANE -->
    <div id="paneR" style="display:none">
      <label>YOUR NAME</label>
      <input id="rn" placeholder="Full name"/>
      <label>GMAIL (@gmail.com) *</label>
      <input id="ru" type="email" placeholder="example@gmail.com"/>
      <label>PASSWORD (min 6 char) *</label>
      <input id="rp" type="password" placeholder="Choose password"/>
      <label>CONFIRM PASSWORD *</label>
      <input id="rp2" type="password" placeholder="Repeat password"/>
      <button class="btn gr" style="width:100%;margin-top:16px;padding:14px" onclick="gmailRegister()">✨ CREATE ACCOUNT</button>
      <div class="info" style="margin-top:12px">Sirf <b>@gmail.com</b> emails accepted. Ek hi email = ek permanent account. Dobara login karo → same data milega.</div>
    </div>

    <div class="err" id="err"></div>

    <div class="or">OR</div>
    <a class="btn gd" href="/payment" style="width:100%">💳 BUY ACCESS</a>
    <a class="btn" href="${esc(CFG.TG_LINK)}" target="_blank" style="width:100%;margin-top:10px">💬 SUPPORT · @BRONX_ULTRA</a>

    <button class="admin-toggle" onclick="toggleAdmin()">🔒 ADMIN LOGIN</button>
    <div class="admin-form" id="adminForm">
      <label>ADMIN USERNAME</label>
      <input id="au" placeholder="admin"/>
      <label>ADMIN PASSWORD</label>
      <input id="ap" type="password"/>
      <button class="btn red" style="width:100%;margin-top:12px" onclick="adminLogin()">LOGIN AS ADMIN</button>
      <div class="err" id="aerr"></div>
    </div>
  </div>
</div>
${BROADCAST_JS}
<script>
loadBroadcast();
function sw(t){
  document.getElementById('paneG').style.display = (t==='g')?'block':'none';
  document.getElementById('paneM').style.display = (t==='m')?'block':'none';
  document.getElementById('paneR').style.display = (t==='r')?'block':'none';
  document.getElementById('tabG').classList.toggle('on', t==='g');
  document.getElementById('tabM').classList.toggle('on', t==='m' || t==='r');
}
function showErr(msg, id){
  var e = document.getElementById(id||'err');
  e.textContent = msg; e.classList.add('show');
  setTimeout(function(){ e.classList.remove('show'); }, 5000);
}
function toggleAdmin(){ document.getElementById('adminForm').classList.toggle('show'); }
async function getFP(){
  try{
    var d=[navigator.userAgent,navigator.language,screen.width+'x'+screen.height,screen.colorDepth,new Date().getTimezoneOffset(),navigator.hardwareConcurrency||0,navigator.platform||''].join('|');
    var b=await crypto.subtle.digest('SHA-256', new TextEncoder().encode(d));
    return Array.from(new Uint8Array(b)).map(function(x){return x.toString(16).padStart(2,'0');}).join('');
  }catch(e){
    var x=localStorage.getItem('bx_fp'); if(!x){ x='fp-'+Math.random().toString(36).slice(2)+Date.now(); localStorage.setItem('bx_fp',x);} return x;
  }
}
async function handleGoogle(response){
  try{
    var fp = await getFP();
    var r = await fetch('/api/auth/google', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ credential: response.credential, fp: fp, ua: navigator.userAgent, device: navigator.platform||'' })
    });
    var j = await r.json();
    if (j.ok){ location.href='/'; return; }
    showErr(j.error||'Login failed');
  }catch(e){ showErr('Network error: '+e.message); }
}
async function gmailLogin(){
  var u = document.getElementById('mu').value.trim().toLowerCase();
  var p = document.getElementById('mp').value;
  if (!u || !p){ showErr('Gmail aur password required'); return; }
  if (!/^[a-z0-9._%+-]+@gmail\\.com$/.test(u)){ showErr('Sirf @gmail.com allowed'); return; }
  try{
    var fp = await getFP();
    var r = await fetch('/api/auth/gmail/login', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ email: u, password: p, fp: fp, ua: navigator.userAgent, device: navigator.platform||'' })
    });
    var j = await r.json();
    if (j.ok){ location.href='/'; return; }
    showErr(j.error||'Login failed');
  }catch(e){ showErr('Network error: '+e.message); }
}
async function gmailRegister(){
  var n = document.getElementById('rn').value.trim();
  var u = document.getElementById('ru').value.trim().toLowerCase();
  var p = document.getElementById('rp').value;
  var p2 = document.getElementById('rp2').value;
  if (!u || !p){ showErr('Gmail aur password required'); return; }
  if (!/^[a-z0-9._%+-]+@gmail\\.com$/.test(u)){ showErr('Sirf @gmail.com allowed'); return; }
  if (p.length < 6){ showErr('Password min 6 characters'); return; }
  if (p !== p2){ showErr('Passwords match nahi kar rahe'); return; }
  try{
    var fp = await getFP();
    var r = await fetch('/api/auth/gmail/register', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ email: u, password: p, name: n, fp: fp, ua: navigator.userAgent, device: navigator.platform||'' })
    });
    var j = await r.json();
    if (j.ok){ location.href='/'; return; }
    showErr(j.error||'Registration failed');
  }catch(e){ showErr('Network error: '+e.message); }
}
async function adminLogin(){
  var u = document.getElementById('au').value.trim(), p = document.getElementById('ap').value;
  if (!u || !p){ showErr('Missing credentials', 'aerr'); return; }
  try{
    var r = await fetch('/api/admin/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ u:u, p:p }) });
    var j = await r.json();
    if (j.ok){ location.href='/admin'; return; }
    showErr(j.error||'Login failed', 'aerr');
  }catch(e){ showErr(e.message, 'aerr'); }
}
</script></body></html>`;

/* ============================================================
   HTML · LANDING
   ============================================================ */
const LANDING_HTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>BRONX ULTRA · OSINT</title>
<style>
${CSS}
header{padding:16px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;position:relative;z-index:1}
.brand{display:flex;align-items:center;gap:10px}
.logo2{width:44px;height:44px;display:grid;place-items:center;font-size:20px;background:linear-gradient(135deg,rgba(239,43,58,.6),#000);border:1px solid rgba(239,43,58,.7);clip-path:polygon(50% 0,100% 25%,100% 75%,50% 100%,0 75%,0 25%);box-shadow:0 0 20px rgba(239,43,58,.5)}
.brand-name{font-weight:900;letter-spacing:.15em;font-size:22px;line-height:1}
.brand-name .r{color:#ef2b3a}
.brand-sub{color:#22d3ee;letter-spacing:.4em;font-size:10px;margin-top:4px}
.hero{text-align:center;padding:16px;position:relative;z-index:1}
.title{font-family:Impact,"Arial Black",sans-serif;font-weight:900;font-size:clamp(40px,10vw,120px);line-height:1;text-shadow:0 0 40px rgba(239,43,58,.45)}
.title .red{color:#ef2b3a}
.tag{display:inline-flex;align-items:center;gap:12px;margin-top:16px;color:#22d3ee;letter-spacing:.3em;font-size:12px}
.tag .ln{height:1px;width:50px;background:#ef2b3a;box-shadow:0 0 8px #ef2b3a}
.cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:24px auto 0;max-width:1200px;padding:0 16px;position:relative;z-index:1}
@media(min-width:700px){.cards{grid-template-columns:repeat(4,minmax(0,1fr))}}
@media(min-width:1024px){.cards{grid-template-columns:repeat(5,minmax(0,1fr))}}
.card{--a:#22d3ee;display:flex;flex-direction:column;align-items:center;padding:20px 12px;border-radius:14px;background:linear-gradient(180deg,rgba(0,0,0,.6),rgba(0,0,0,.85));border:1px solid color-mix(in oklab,var(--a) 55%,transparent);box-shadow:0 0 0 1px color-mix(in oklab,var(--a) 25%,transparent),0 0 30px color-mix(in oklab,var(--a) 30%,transparent);transition:transform .25s;cursor:pointer}
.card:hover{transform:translateY(-3px)}
.card .ic{width:68px;height:68px;border-radius:999px;display:grid;place-items:center;border:2px solid var(--a);background:color-mix(in oklab,var(--a) 12%,#000);box-shadow:0 0 25px color-mix(in oklab,var(--a) 50%,transparent);font-size:30px;color:var(--a)}
.card h3{margin-top:14px;font-size:15px;font-weight:800;letter-spacing:.05em;text-align:center}
.card .sub{margin-top:4px;font-size:10px;letter-spacing:.2em;color:var(--a);text-align:center}
.card .btn{margin-top:16px;width:100%;padding:10px;font-size:11px}
.popup{position:fixed;inset:0;z-index:100;display:none;align-items:center;justify-content:center;background:rgba(2,4,8,.85);backdrop-filter:blur(10px);padding:20px}
.popup.show{display:flex}
.popup-box{max-width:400px;width:100%;padding:28px;border-radius:16px;background:linear-gradient(180deg,rgba(14,27,42,.95),rgba(8,18,31,.95));border:1px solid rgba(34,211,238,.5);text-align:center}
.popup-box .ic{font-size:44px}
.popup-box h3{margin-top:12px;font-size:16px;letter-spacing:.15em;font-weight:900;color:#22d3ee}
.popup-box p{margin-top:12px;font-size:13px;color:#94a3b8;line-height:1.6}
.popup-box .btns{display:flex;gap:10px;margin-top:20px;flex-wrap:wrap}
.popup-box .btn{flex:1;min-width:120px}
footer{margin-top:40px;border-top:1px solid rgba(255,255,255,.1);background:rgba(0,0,0,.6);padding:20px 16px;text-align:center;font-size:11px;letter-spacing:.2em;color:#94a3b8;position:relative;z-index:1}
</style></head><body>
<header>
  <div class="brand">
    <div class="logo2">🕵️</div>
    <div>
      <div class="brand-name"><span class="r">BRONX</span> ULTRA</div>
      <div class="brand-sub">@BRONX_ULTRA</div>
    </div>
  </div>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <a class="chip gd" href="/payment">💳 BUY ACCESS</a>
    <a class="chip" href="${esc(CFG.TG_LINK)}" target="_blank">💬 SUPPORT</a>
    <a class="chip red" href="/login">🔐 SIGN IN</a>
  </div>
</header>
<section class="hero">
  <h1 class="title"><span class="red">BRONX</span> ULTRA</h1>
  <div class="tag"><span class="ln"></span>SEARCH · ANALYZE · INVESTIGATE<span class="ln"></span></div>
</section>
<section class="cards" id="cards"></section>
<footer>© BRONX ULTRA · @BRONX_ULTRA · v5.5</footer>

<div class="popup" id="popup">
  <div class="popup-box">
    <div class="ic">🔐</div>
    <h3 id="popupTitle">LOGIN REQUIRED</h3>
    <p id="popupMsg">Ye feature use karne ke liye pehle login karna hoga.</p>
    <div class="btns">
      <a class="btn" href="/login">🔐 SIGN IN</a>
      <a class="btn gd" href="/payment">💳 BUY</a>
    </div>
    <button class="btn red" style="width:100%;margin-top:10px" onclick="closePopup()">✕ CLOSE</button>
  </div>
</div>
${BROADCAST_JS}
<script>
var FEATURES = [];
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
async function loadFeatures(){
  try{ var r = await fetch('/api/features'); var j = await r.json(); FEATURES = j.features||[]; }catch(e){ FEATURES = []; }
  render();
}
function render(){
  var h='';
  for (var i=0;i<FEATURES.length;i++){
    var f = FEATURES[i];
    h += '<div class="card" style="--a:'+esc(f.color||'#22d3ee')+'" onclick="tryFeature(\\''+esc(f.id)+'\\')">'
      + '<div class="ic">'+esc(f.emoji||'🔍')+'</div>'
      + '<h3>'+esc(f.name)+'</h3>'
      + '<div class="sub">'+esc(f.hint||'')+'</div>'
      + '<button class="btn">🔓 OPEN</button>'
      + '</div>';
  }
  document.getElementById('cards').innerHTML = h || '<div style="grid-column:1/-1;text-align:center;padding:40px;color:#94a3b8">No features configured</div>';
}
function tryFeature(id){
  var f = FEATURES.find(function(x){return x.id===id;});
  if (!f) return;
  document.getElementById('popupTitle').textContent = 'LOGIN REQUIRED';
  document.getElementById('popupMsg').textContent = '"'+f.name+'" use karne ke liye login karein.';
  document.getElementById('popup').classList.add('show');
}
function closePopup(){ document.getElementById('popup').classList.remove('show'); }
loadBroadcast();
loadFeatures();
</script></body></html>`;

/* ============================================================
   HTML · DASHBOARD
   ============================================================ */
const DASHBOARD_HTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>BRONX ULTRA · Dashboard</title>
<style>
${CSS}
header{padding:16px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;position:relative;z-index:1}
.brand{display:flex;align-items:center;gap:10px}
.logo2{width:44px;height:44px;display:grid;place-items:center;font-size:20px;background:linear-gradient(135deg,rgba(239,43,58,.6),#000);border:1px solid rgba(239,43,58,.7);clip-path:polygon(50% 0,100% 25%,100% 75%,50% 100%,0 75%,0 25%);box-shadow:0 0 20px rgba(239,43,58,.5)}
.brand-name{font-weight:900;letter-spacing:.15em;font-size:22px;line-height:1}
.brand-name .r{color:#ef2b3a}
.brand-sub{color:#22d3ee;letter-spacing:.4em;font-size:10px;margin-top:4px}
.hero{text-align:center;padding:16px;position:relative;z-index:1}
.title{font-family:Impact,"Arial Black",sans-serif;font-weight:900;font-size:clamp(36px,9vw,100px);line-height:1;text-shadow:0 0 40px rgba(239,43,58,.45)}
.title .red{color:#ef2b3a}
.tag{display:inline-flex;align-items:center;gap:12px;margin-top:16px;color:#22d3ee;letter-spacing:.3em;font-size:12px}
.tag .ln{height:1px;width:50px;background:#ef2b3a;box-shadow:0 0 8px #ef2b3a}
.cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:24px auto 0;max-width:1200px;padding:0 16px;position:relative;z-index:1}
@media(min-width:700px){.cards{grid-template-columns:repeat(4,minmax(0,1fr))}}
@media(min-width:1024px){.cards{grid-template-columns:repeat(5,minmax(0,1fr))}}
.card{--a:#22d3ee;display:flex;flex-direction:column;align-items:center;padding:20px 12px;border-radius:14px;background:linear-gradient(180deg,rgba(0,0,0,.6),rgba(0,0,0,.85));border:1px solid color-mix(in oklab,var(--a) 55%,transparent);box-shadow:0 0 0 1px color-mix(in oklab,var(--a) 25%,transparent),0 0 30px color-mix(in oklab,var(--a) 30%,transparent);transition:.25s}
.card:hover{transform:translateY(-3px)}
.card .ic{width:68px;height:68px;border-radius:999px;display:grid;place-items:center;border:2px solid var(--a);background:color-mix(in oklab,var(--a) 12%,#000);box-shadow:0 0 25px color-mix(in oklab,var(--a) 50%,transparent);font-size:30px;color:var(--a)}
.card h3{margin-top:14px;font-size:15px;font-weight:800;letter-spacing:.05em;text-align:center}
.card .sub{margin-top:4px;font-size:10px;letter-spacing:.2em;color:var(--a);text-align:center}
.card .btn{margin-top:16px;width:100%;padding:10px;font-size:11px}
footer{margin-top:40px;border-top:1px solid rgba(255,255,255,.1);background:rgba(0,0,0,.6);padding:20px 16px;text-align:center;font-size:11px;letter-spacing:.2em;color:#94a3b8;position:relative;z-index:1}

.overlay{position:fixed;inset:0;z-index:50;display:none;flex-direction:column;overflow-y:auto;background:linear-gradient(180deg,#05070A,#08121F 55%,#0E1B2A)}
.overlay.open{display:flex}
.ov-head{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 16px;border-bottom:1px solid rgba(255,255,255,.1);background:rgba(0,0,0,.5);position:sticky;top:0;z-index:10}
.ov-body{max-width:900px;margin:0 auto;padding:32px 16px 60px;width:100%;text-align:center}
.big-ic{width:100px;height:100px;border-radius:999px;display:grid;place-items:center;margin:0 auto;font-size:44px;border:2px solid var(--a,#22d3ee);background:color-mix(in oklab,var(--a,#22d3ee) 12%,#000);box-shadow:0 0 40px var(--a,#22d3ee);color:var(--a,#22d3ee)}
.ov-body h1{margin-top:20px;font-size:clamp(22px,5vw,34px);font-weight:900;letter-spacing:.03em;display:flex;justify-content:center;align-items:center;gap:12px}
.ov-body .hint{margin-top:6px;font-size:11px;letter-spacing:.3em;color:var(--a,#22d3ee)}
.search-box{margin-top:26px;display:flex;align-items:center;gap:10px;padding:12px 14px;border:1px solid var(--a,#22d3ee);border-radius:10px;background:rgba(0,0,0,.6);box-shadow:inset 0 0 30px color-mix(in oklab,var(--a,#22d3ee) 25%,transparent)}
.search-box input{flex:1;min-width:0;background:transparent;border:0;outline:0;color:#fff;font-size:16px}
.search-box input.vi{text-transform:uppercase}
.go{padding:10px 16px;font-size:12px;font-weight:800;letter-spacing:.2em;background:transparent;border:1px solid var(--a,#22d3ee);color:var(--a,#22d3ee);border-radius:6px;cursor:pointer;flex-shrink:0}
.go:hover{background:color-mix(in oklab,var(--a,#22d3ee) 15%,transparent)}
.go:disabled{opacity:.3;cursor:not-allowed}
.err-msg{margin-top:10px;color:#ef2b3a;font-size:12px;text-align:left}
.loading{display:flex;flex-direction:column;align-items:center;gap:10px;padding:36px 0;letter-spacing:.3em;font-size:12px}
.spin{width:32px;height:32px;border-radius:999px;border:3px solid rgba(255,255,255,.15);border-top-color:var(--a,#22d3ee);animation:sp 1s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}
.idle{padding:28px;text-align:center;color:rgba(255,255,255,.6);font-size:14px;border:1px solid rgba(255,255,255,.1);border-radius:10px;background:rgba(0,0,0,.4);margin-top:24px}
.res-wrap{max-width:1200px;margin:0 auto;padding:24px 16px 60px;text-align:left}
.glass{border-radius:18px;border:1px solid rgba(255,255,255,.08);background:linear-gradient(180deg,rgba(14,27,42,.72),rgba(8,18,31,.5));box-shadow:0 30px 80px rgba(0,0,0,.55),0 0 60px rgba(0,229,255,.07)}
.res-head{padding:16px 20px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;border-bottom:1px solid rgba(255,255,255,.08)}
.res-title{display:flex;align-items:center;gap:12px;font-weight:800;letter-spacing:.1em}
.res-title .mk{width:32px;height:32px;border-radius:9px;display:grid;place-items:center;background:linear-gradient(135deg,#ef2b3a,#22d3ee);font-size:16px}
.res-title .nm span{color:#22d3ee}
.target-chip{padding:6px 12px;border-radius:8px;background:rgba(0,229,255,.08);border:1px solid rgba(0,229,255,.45);color:#7fefff;font-family:ui-monospace,monospace;font-size:12px;font-weight:700}
.res-body{padding:8px 12px 16px}
.rrow{display:grid;grid-template-columns:200px 1fr;gap:16px;padding:12px 14px;border-radius:10px;align-items:start;animation:rowIn .3s ease both}
.rrow+.rrow{border-top:1px solid rgba(255,255,255,.05)}
.rrow:hover{background:rgba(0,229,255,.03)}
@keyframes rowIn{from{opacity:0;transform:translateX(-6px)}to{opacity:1;transform:none}}
.rlbl{font-size:11px;letter-spacing:.18em;font-weight:700;color:#22d3ee;text-transform:uppercase;padding-top:2px}
.rval{font-size:14px;color:#F8FAFC;font-weight:600;line-height:1.55;word-break:break-word}
.rval.mono{font-family:ui-monospace,monospace;color:#7fefff;letter-spacing:.05em}
.rval.link{color:#7fefff;word-break:break-all}
.rval img{max-width:160px;max-height:160px;border-radius:12px;border:1px solid rgba(255,255,255,.15)}
.res-foot{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;padding:12px 20px;border-top:1px solid rgba(255,255,255,.06);color:rgba(255,255,255,.4);font-family:ui-monospace,monospace;font-size:11px;letter-spacing:.15em}
.res-error{padding:48px 24px;text-align:center;color:#FF2E63;font-size:15px;font-weight:600;border:1px solid rgba(255,46,99,.3);border-radius:16px;background:rgba(255,46,99,.05);margin-top:22px}
.rbtn{display:inline-flex;align-items:center;gap:6px;padding:8px 12px;border-radius:10px;font-size:11px;font-weight:700;letter-spacing:.14em;color:#e6faff;cursor:pointer;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.14);font-family:inherit;text-decoration:none}
.rbtn:hover{border-color:rgba(0,229,255,.5)}
.rbtn.primary{background:linear-gradient(135deg,rgba(0,229,255,.22),rgba(59,130,246,.22));border-color:rgba(0,229,255,.5)}

.drawer-mask{position:fixed;inset:0;background:rgba(2,4,8,.6);backdrop-filter:blur(6px);z-index:80;display:none}
.drawer-mask.show{display:block}
.drawer{position:fixed;top:0;right:0;bottom:0;width:400px;max-width:100%;background:linear-gradient(180deg,#08121F,#05070A);border-left:1px solid rgba(34,211,238,.35);z-index:81;transform:translateX(100%);transition:transform .35s;overflow-y:auto;padding:24px}
.drawer.open{transform:translateX(0)}
.drawer h2{font-size:13px;letter-spacing:.22em;color:#22d3ee;margin-bottom:14px;font-weight:800}
.acct-row{padding:12px 0;border-bottom:1px solid rgba(255,255,255,.08);display:flex;justify-content:space-between;gap:10px;font-size:12px}
.acct-row .lbl{color:#94a3b8;letter-spacing:.15em;font-weight:700}
.acct-row .val{color:#fff;text-align:right;word-break:break-all;max-width:60%}
.email-box{padding:14px;border-radius:12px;background:rgba(34,211,238,.06);border:1px solid rgba(34,211,238,.3);display:flex;align-items:center;gap:12px;margin-bottom:14px}
.email-box .av{width:44px;height:44px;border-radius:50%;background:linear-gradient(135deg,#ef2b3a,#22d3ee);display:grid;place-items:center;font-weight:900;font-size:18px}
.email-box .txt{flex:1;min-width:0}
.email-box .em{font-size:13px;font-weight:700;word-break:break-all}
.email-box .nm{font-size:11px;color:#94a3b8;margin-top:2px}
.usage-item{padding:10px 12px;border-radius:8px;background:rgba(0,0,0,.4);border:1px solid rgba(255,255,255,.06);display:flex;justify-content:space-between;align-items:center;font-size:12px;margin-top:8px}
.usage-item .cnt{color:#7fefff;font-weight:800;font-size:14px}
@media(max-width:700px){.rrow{grid-template-columns:1fr;gap:4px;padding:10px 12px}}
</style></head><body>
<header>
  <div class="brand">
    <div class="logo2">🕵️</div>
    <div>
      <div class="brand-name"><span class="r">BRONX</span> ULTRA</div>
      <div class="brand-sub">@BRONX_ULTRA</div>
    </div>
  </div>
  <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
    <button class="chip" onclick="openDrawer()"><span class="dot green"></span><span id="userTxt">LOADING</span></button>
    <a class="chip gd" href="/payment">💳 BUY / RENEW</a>
    <button class="chip red" onclick="doLogout()">⏻ LOGOUT</button>
  </div>
</header>

<section class="hero">
  <h1 class="title"><span class="red">BRONX</span> ULTRA</h1>
  <div class="tag"><span class="ln"></span>SEARCH · ANALYZE · INVESTIGATE<span class="ln"></span></div>
</section>

<div id="accessBanner" style="max-width:1100px;margin:16px auto 0;padding:0 16px;position:relative;z-index:1"></div>

<section class="cards" id="cards"></section>
<footer>© BRONX ULTRA · @BRONX_ULTRA · v5.5</footer>

<div class="overlay" id="overlay">
  <div class="ov-head">
    <button class="chip" onclick="closeOverlay()">← BACK</button>
    <div><span style="color:#ef2b3a;font-weight:900;letter-spacing:.2em">BRONX</span> <span style="font-weight:900;letter-spacing:.2em">ULTRA</span></div>
    <span class="chip" id="hintChip"><span class="dot"></span><span id="hintText">READY</span></span>
  </div>
  <div class="ov-body" id="ovBody"></div>
</div>

<div class="drawer-mask" id="drawerMask" onclick="closeDrawer()"></div>
<div class="drawer" id="drawer">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
    <h2>👤 MY ACCOUNT</h2>
    <button class="chip red" onclick="closeDrawer()">✕</button>
  </div>
  <div id="drawerBody"></div>
</div>

${BROADCAST_JS}
<script>
var FEATURES = [];
var ME = null;
var cur = null;

function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function isURL(v){ return typeof v==='string' && /^https?:\\/\\//i.test(v); }
function isImgURL(v){ return isURL(v) && (/\\.(jpg|jpeg|png|webp|gif|bmp)(\\?|$)/i.test(v) || /(pfp|avatar|profile|cover|image|photo|thumb)/i.test(v)); }

async function loadMe(){
  try{
    var r = await fetch('/api/me');
    if (!r.ok){ location.href='/login'; return; }
    ME = await r.json();
  }catch(e){ location.href='/login'; return; }
  var label = ME.name || ME.email || 'user';
  document.getElementById('userTxt').textContent = label.toUpperCase().slice(0, 22);
  renderAccessBanner();
}
function renderAccessBanner(){
  var el = document.getElementById('accessBanner');
  if (!ME) return;
  if (ME.accessActive){
    var exp = ME.expiry ? new Date(ME.expiry).toLocaleString() : 'Active';
    el.innerHTML = '<div style="padding:12px 18px;border-radius:10px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.4);color:#86efac;font-size:12px;letter-spacing:.08em;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap"><span>✅ <b>ACCESS ACTIVE</b> · '+esc(exp)+'</span><span>Token: <span style="font-family:ui-monospace,monospace">'+esc(ME.token||'')+'</span></span></div>';
  } else {
    el.innerHTML = '<div style="padding:12px 18px;border-radius:10px;background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.4);color:#fcd34d;font-size:12px;letter-spacing:.08em;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap"><span>⚠ <b>NO ACTIVE ACCESS</b> · Buy a plan to unlock all features</span><a href="/payment" style="color:#eab308;font-weight:800;text-decoration:underline">BUY NOW →</a></div>';
  }
}
function renderCards(){
  var h='';
  for (var i=0;i<FEATURES.length;i++){
    var f = FEATURES[i];
    h += '<div class="card" style="--a:'+esc(f.color||'#22d3ee')+'" onclick="openFeature(\\''+esc(f.id)+'\\')">'
      + '<div class="ic">'+esc(f.emoji||'🔍')+'</div>'
      + '<h3>'+esc(f.name)+'</h3>'
      + '<div class="sub">'+esc(f.hint||'')+'</div>'
      + '<button class="btn">🚀 SEARCH NOW</button>'
      + '</div>';
  }
  document.getElementById('cards').innerHTML = h || '<div style="grid-column:1/-1;text-align:center;padding:40px;color:#94a3b8">No features configured</div>';
}

function openFeature(id){
  var f = FEATURES.find(function(x){return x.id===id;});
  if (!f) return;
  if (!ME.accessActive){ location.href = '/payment?feature=' + encodeURIComponent(f.id); return; }
  cur = f;
  var body = document.getElementById('ovBody');
  document.getElementById('overlay').classList.add('open');
  document.body.style.overflow='hidden';
  document.getElementById('hintText').textContent = f.hint || '';
  body.innerHTML = '<div class="big-ic" style="--a:'+esc(f.color||'#22d3ee')+'">'+esc(f.emoji||'🔍')+'</div>'
    +'<h1>'+esc(f.emoji||'🔍')+' '+esc(f.name)+'</h1>'
    +'<div class="hint" style="--a:'+esc(f.color||'#22d3ee')+'">'+esc(f.hint||'')+'</div>'
    +'<div class="search-box" id="searchBox" style="--a:'+esc(f.color||'#22d3ee')+'">'
    +'<input id="ovInput" placeholder="'+esc(f.placeholder||'Enter value')+'" autocomplete="off" '+(f.upper?'class="vi"':'')+'/>'
    +'<button class="go" id="goBtn" style="--a:'+esc(f.color||'#22d3ee')+'">SEARCH</button>'
    +'</div>'
    +'<div class="err-msg" id="errText" style="display:none"></div>'
    +'<div id="stateBox"><div class="idle">Query daalein aur SEARCH dabayein.</div></div>';
  document.getElementById('ovInput').addEventListener('keydown', function(e){ if (e.key==='Enter') runSearch(); });
  document.getElementById('goBtn').addEventListener('click', runSearch);
  setTimeout(function(){ var i=document.getElementById('ovInput'); if(i)i.focus(); }, 50);
}
function closeOverlay(){ document.getElementById('overlay').classList.remove('open'); document.body.style.overflow=''; cur=null; }

async function runSearch(){
  if (!cur) return;
  var raw = document.getElementById('ovInput').value.trim();
  var err = document.getElementById('errText');
  var st = document.getElementById('stateBox');
  err.style.display = 'none';
  if (!raw){ err.textContent = 'Value daalein'; err.style.display='block'; return; }
  if (cur.type === 'number'){
    raw = raw.replace(/\\D/g,'');
    if (cur.len && raw.length !== cur.len){ err.textContent = 'Exactly '+cur.len+' digits chahiye'; err.style.display='block'; return; }
  } else if (cur.upper){ raw = raw.toUpperCase(); }
  var goBtn = document.getElementById('goBtn'); goBtn.disabled=true;
  st.innerHTML = '<div class="loading"><div class="spin" style="--a:'+esc(cur.color||'#22d3ee')+'"></div><div>CONNECTING TO SECURE NODES...</div></div>';
  try{
    var url = '/api/lookup?feature=' + encodeURIComponent(cur.id) + '&q=' + encodeURIComponent(raw);
    var r = await fetch(url, { headers:{ 'X-Requested-With':'XMLHttpRequest' }});
    if (r.status === 401){ st.innerHTML='<div class="idle" style="color:#FF2E63">Session expired. Redirecting...</div>'; setTimeout(function(){location.href='/login';},1500); return; }
    if (r.status === 402){ location.href = '/payment?feature=' + encodeURIComponent(cur.id); return; }
    var data = await r.json();
    renderResults(data, raw);
  }catch(e){ st.innerHTML='<div class="idle" style="color:#FF2E63">Error: '+esc(e.message)+'</div>'; }
  finally{ goBtn.disabled=false; }
}

function flatten(obj, prefix, out){
  if (obj===null||obj===undefined) return;
  if (typeof obj !== 'object'){ out.push([prefix, obj]); return; }
  if (Array.isArray(obj)){ for(var i=0;i<obj.length;i++) flatten(obj[i], prefix+'['+(i+1)+']', out); return; }
  var keys=Object.keys(obj);
  for(var k=0;k<keys.length;k++){
    var key=keys[k], val=obj[key];
    var pk=prefix?prefix+'.'+key:key;
    if (val!==null && typeof val==='object') flatten(val, pk, out);
    else if (val!==undefined && val!==null && val!=='') out.push([pk, val]);
  }
}
function humanKey(k){ return k.replace(/[._]/g,' · ').replace(/\\[/g,' ').replace(/\\]/g,'').replace(/([A-Z])/g,' $1').replace(/\\s+/g,' ').replace(/\\b\\w/g,function(m){return m.toUpperCase();}).trim(); }

function renderResults(data, query){
  var body = document.getElementById('ovBody');
  if (data && (data.status===false||data.success===false||data.error) && !data.data && !data.result){
    var msg = data.error || data.msg || data.message || 'No data found';
    body.innerHTML = '<div class="res-wrap"><div class="glass res-error">'+esc(msg)+'</div><div style="text-align:center;margin-top:20px"><button class="rbtn primary" onclick="closeOverlay()">← BACK</button></div></div>';
    return;
  }
  var rows=[]; flatten(data,'',rows);
  if (!rows.length){ body.innerHTML='<div class="res-wrap"><div class="glass res-error">Empty response</div></div>'; return; }
  var html='<div class="res-wrap"><div class="glass"><div class="res-head"><div class="res-title"><div class="mk">🕵️</div><div class="nm">BRONX <span>ULTRA</span></div></div><span class="target-chip">'+esc(query)+'</span><div style="display:flex;gap:8px"><button class="rbtn" onclick="copyAll()">📋 EXPORT</button><button class="rbtn primary" onclick="closeOverlay()">← BACK</button></div></div><div class="res-body">';
  for (var i=0;i<rows.length;i++){
    var k=rows[i][0], v=rows[i][1], vh;
    if (isImgURL(v)) vh='<img referrerpolicy="no-referrer" src="'+esc(v)+'" onclick="window.open(this.src,\\'_blank\\')"/>';
    else if (isURL(v)) vh='<a class="rval link" href="'+esc(v)+'" target="_blank" rel="noreferrer">'+esc(v)+'</a>';
    else vh='<div class="rval mono">'+esc(String(v))+'</div>';
    html+='<div class="rrow" style="animation-delay:'+(i*0.02)+'s"><div class="rlbl">'+esc(humanKey(k))+'</div><div>'+vh+'</div></div>';
  }
  html+='</div><div class="res-foot"><div>BRONX ULTRA · SESSION '+Math.random().toString(36).slice(2,8).toUpperCase()+'</div><div>'+rows.length+' FIELDS · '+new Date().toLocaleString()+'</div></div></div></div>';
  body.innerHTML = html;
}
async function copyAll(){
  var rows=document.querySelectorAll('.rrow'), t='════ BRONX ULTRA EXPORT ════\\n\\n';
  for (var i=0;i<rows.length;i++){
    var k=rows[i].querySelector('.rlbl').textContent.trim();
    var v=rows[i].querySelector('.rval');
    if (k&&v) t+=k+': '+v.textContent.trim()+'\\n';
  }
  t+='\\n© BRONX ULTRA';
  try{ await navigator.clipboard.writeText(t); alert('Copied!'); }catch(e){ alert('Copy failed'); }
}

async function openDrawer(){
  document.getElementById('drawer').classList.add('open');
  document.getElementById('drawerMask').classList.add('show');
  var body = document.getElementById('drawerBody');
  body.innerHTML = '<div class="idle">Loading...</div>';
  try{
    var r = await fetch('/api/account/info');
    var j = await r.json();
    if (!j.ok){ body.innerHTML='<div class="idle">Failed</div>'; return; }
    var u = j.user || {};
    var usage = j.usage || {};
    var deviceList = (u.devices||[]).map(function(d){
      return '<div class="acct-row"><span class="lbl">'+esc(d.device||'Device')+'</span><span class="val">'+esc((d.ip||'')+' · '+new Date(d.lastSeen||d.added).toLocaleDateString())+'</span></div>';
    }).join('') || '<div class="acct-row"><span class="lbl">Devices</span><span class="val">—</span></div>';
    var usageHtml = '';
    if (Object.keys(usage).length){
      for (var k in usage){
        usageHtml += '<div class="usage-item"><span>'+esc(k)+'</span><span class="cnt">'+usage[k]+'</span></div>';
      }
    } else usageHtml = '<div class="usage-item"><span>No usage yet</span><span class="cnt">0</span></div>';

    body.innerHTML =
      '<div class="email-box">'
        + '<div class="av">'+esc((u.name||u.email||'U').charAt(0).toUpperCase())+'</div>'
        + '<div class="txt"><div class="em">'+esc(u.email||'—')+'</div><div class="nm">'+esc(u.name||'')+'</div></div>'
      + '</div>'
      + '<div class="acct-row"><span class="lbl">Status</span><span class="val">'+(u.accessActive?'<span style="color:#86efac">✅ ACTIVE</span>':'<span style="color:#fcd34d">⚠ NO ACCESS</span>')+'</span></div>'
      + '<div class="acct-row"><span class="lbl">Expiry</span><span class="val">'+(u.expiry ? new Date(u.expiry).toLocaleString() : '—')+'</span></div>'
      + '<div class="acct-row"><span class="lbl">Token</span><span class="val" style="font-family:ui-monospace,monospace">'+esc(u.token||'—')+'</span></div>'
      + '<div class="acct-row"><span class="lbl">Joined</span><span class="val">'+new Date(u.createdAt||Date.now()).toLocaleDateString()+'</span></div>'
      + '<h2 style="margin-top:22px">📱 DEVICES</h2>' + deviceList
      + '<h2 style="margin-top:22px">📊 FEATURE USAGE</h2>' + usageHtml
      + '<div style="margin-top:22px;display:flex;flex-direction:column;gap:10px">'
      +   '<a class="btn gd" href="/payment">💳 BUY / RENEW</a>'
      +   '<button class="btn red" onclick="doLogout()">⏻ LOGOUT</button>'
      + '</div>';
  }catch(e){ body.innerHTML='<div class="idle">Error: '+esc(e.message)+'</div>'; }
}
function closeDrawer(){
  document.getElementById('drawer').classList.remove('open');
  document.getElementById('drawerMask').classList.remove('show');
}
async function doLogout(){
  try{ await fetch('/api/logout', { method:'POST' }); }catch(e){}
  location.href = '/login';
}

async function loadFeatures(){
  try{ var r=await fetch('/api/features'); var j=await r.json(); FEATURES=j.features||[]; }catch(e){ FEATURES=[]; }
  renderCards();
}
(async function init(){
  await loadMe();
  await loadFeatures();
  loadBroadcast();
})();
</script></body></html>`;

/* ============================================================
   HTML · PAYMENT
   ============================================================ */
const PAYMENT_HTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>BRONX ULTRA · Payment</title>
<style>
${CSS}
header{padding:16px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;position:relative;z-index:1}
.brand{display:flex;align-items:center;gap:10px}
.logo2{width:44px;height:44px;display:grid;place-items:center;font-size:20px;background:linear-gradient(135deg,rgba(234,179,8,.6),#000);border:1px solid rgba(234,179,8,.8);clip-path:polygon(50% 0,100% 25%,100% 75%,50% 100%,0 75%,0 25%);box-shadow:0 0 20px rgba(234,179,8,.5)}
.brand-name{font-weight:900;letter-spacing:.15em;font-size:22px;line-height:1}
.brand-name .r{color:#ef2b3a}
.brand-sub{color:#eab308;letter-spacing:.4em;font-size:10px;margin-top:4px}
.hero{text-align:center;padding:20px 16px;position:relative;z-index:1}
.hero h1{font-size:clamp(28px,6vw,44px);font-weight:900;letter-spacing:.05em}
.hero h1 span{color:#eab308}
.hero p{margin-top:8px;color:#94a3b8;font-size:12px;letter-spacing:.15em}
.container{max-width:1100px;margin:0 auto;padding:0 16px;position:relative;z-index:1}
.plans{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:20px}
@media(min-width:640px){.plans{grid-template-columns:repeat(3,minmax(0,1fr))}}
.plan{padding:20px 16px;border-radius:14px;background:linear-gradient(180deg,rgba(0,0,0,.6),rgba(0,0,0,.85));border:1px solid rgba(234,179,8,.35);box-shadow:0 0 25px rgba(234,179,8,.15);text-align:center;transition:.25s;cursor:pointer;position:relative}
.plan:hover{transform:translateY(-3px);border-color:rgba(234,179,8,.7);box-shadow:0 0 35px rgba(234,179,8,.35)}
.plan.popular{border-color:rgba(239,43,58,.7);box-shadow:0 0 35px rgba(239,43,58,.35)}
.plan.popular::after{content:"❤️ POPULAR";position:absolute;top:-10px;right:10px;padding:4px 10px;font-size:9px;letter-spacing:.15em;font-weight:800;background:#ef2b3a;color:#fff;border-radius:6px}
.plan .days{font-size:11px;letter-spacing:.3em;color:#eab308;font-weight:800}
.plan .price{margin-top:12px;font-size:28px;font-weight:900;color:#fff;font-family:Impact,sans-serif}
.plan .tag{margin-top:6px;font-size:10px;color:#94a3b8;letter-spacing:.1em}
.plan .buy{margin-top:14px;width:100%;padding:10px;font-size:11px}
.section{max-width:700px;margin:30px auto 0;padding:24px;border-radius:16px;background:linear-gradient(180deg,rgba(14,27,42,.72),rgba(8,18,31,.5));border:1px solid rgba(34,211,238,.35);position:relative;z-index:1}
.section h2{font-size:13px;letter-spacing:.22em;color:#22d3ee;font-weight:800;margin-bottom:14px}
.upi-row{display:flex;align-items:center;gap:10px;padding:12px 14px;border-radius:10px;background:rgba(0,0,0,.5);border:1px solid rgba(34,211,238,.35);margin-bottom:10px}
.upi-row .lbl{font-size:10px;letter-spacing:.22em;color:#94a3b8;font-weight:700}
.upi-row .val{font-family:ui-monospace,monospace;font-size:14px;color:#7fefff;font-weight:700;word-break:break-all;flex:1}
.copy{padding:6px 10px;font-size:10px;letter-spacing:.15em;font-weight:700;border-radius:6px;background:rgba(34,211,238,.1);border:1px solid rgba(34,211,238,.5);color:#7fefff;cursor:pointer;font-family:inherit}
.qr{display:block;margin:16px auto;max-width:220px;width:100%;border-radius:12px;border:1px solid rgba(34,211,238,.4);box-shadow:0 0 30px rgba(34,211,238,.25)}
.apps{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:8px;margin-top:8px}
.app{padding:10px;text-align:center;font-size:11px;font-weight:700;border-radius:10px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.12);color:#e6faff;text-decoration:none;transition:.2s}
.app:hover{background:rgba(34,211,238,.1);border-color:rgba(34,211,238,.5)}
.selected{margin-top:14px;padding:12px;border-radius:10px;background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.4);font-size:12px;color:#fcd34d;letter-spacing:.05em;text-align:center;font-weight:700}
.msg{padding:10px;border-radius:8px;font-size:12px;margin-top:12px;display:none}
.msg.ok{display:block;color:#86efac;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.35)}
.msg.err{display:block;color:#ffb0c4;background:rgba(255,46,99,.08);border:1px solid rgba(255,46,99,.35)}
.success{margin-top:22px;padding:20px;border-radius:12px;background:rgba(34,197,94,.06);border:1px solid rgba(34,197,94,.4);text-align:center;display:none}
.success.show{display:block}
.success .ic{font-size:44px}
.success h3{margin-top:10px;font-size:18px;font-weight:900;color:#86efac;letter-spacing:.1em}
.success .token{margin-top:14px;padding:14px;border-radius:10px;background:rgba(0,0,0,.6);border:1px dashed rgba(34,211,238,.6);font-family:ui-monospace,monospace;font-size:16px;font-weight:800;color:#7fefff;letter-spacing:.08em;word-break:break-all}
.success .creds{margin-top:10px;font-size:11px;color:#94a3b8}
.warn{margin-top:12px;padding:10px;border-radius:8px;background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.4);color:#fcd34d;font-size:12px;text-align:left;line-height:1.5}
footer{margin-top:40px;border-top:1px solid rgba(255,255,255,.1);background:rgba(0,0,0,.6);padding:20px 16px;text-align:center;font-size:11px;letter-spacing:.2em;color:#94a3b8;position:relative;z-index:1}
</style></head><body>
<header>
  <div class="brand">
    <div class="logo2">💳</div>
    <div>
      <div class="brand-name"><span class="r">BRONX</span> ULTRA</div>
      <div class="brand-sub">PAYMENT</div>
    </div>
  </div>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <a class="chip" href="/">🏠 HOME</a>
    <a class="chip red" href="/login">🔐 SIGN IN</a>
  </div>
</header>

<section class="hero">
  <h1><span>PREMIUM</span> ACCESS</h1>
  <p>Instant OSINT access · Unlimited searches · 24/7 support</p>
</section>

<div class="container">
  <div class="plans" id="plans"></div>

  <div class="section">
    <h2>💳 STEP 1 · PAY VIA UPI</h2>
    <div class="upi-row">
      <div style="flex:1">
        <div class="lbl">UPI ID</div>
        <div class="val" id="upiVal">${esc(CFG.UPI_ID)}</div>
      </div>
      <button class="copy" onclick="copyUPI()">COPY</button>
    </div>
    <div class="selected" id="selectedPlan">👉 Upar se plan select karein</div>
    <img class="qr" src="${esc(CFG.QR_IMG)}" alt="QR" onerror="this.style.display='none'"/>
    <div class="apps">
      <a class="app" id="payAny" href="#">Any UPI</a>
      <a class="app" id="payGpay" href="#">GPay</a>
      <a class="app" id="payPhonepe" href="#">PhonePe</a>
      <a class="app" id="payPaytm" href="#">Paytm</a>
      <a class="app" id="payBhim" href="#">BHIM</a>
    </div>
  </div>

  <div class="section">
    <h2>✅ STEP 2 · SUBMIT PROOF</h2>
    <label>UTR / TRANSACTION ID *</label>
    <input id="utr" placeholder="Enter UTR / Txn ID" autocomplete="off"/>
    <label>YOUR GMAIL (@gmail.com) *</label>
    <input id="email" type="email" placeholder="example@gmail.com" autocomplete="email"/>
    <label>TELEGRAM USERNAME / CHAT ID *</label>
    <input id="tg" placeholder="@username or numeric chat id" autocomplete="off"/>
    <button class="btn gr" style="width:100%;margin-top:16px;padding:14px" onclick="submitPayment()">🚀 SUBMIT &amp; GET TOKEN</button>
    <div class="msg" id="pMsg"></div>

    <div class="success" id="success">
      <div class="ic">🎉</div>
      <h3>TOKEN GENERATED</h3>
      <div style="font-size:12px;color:#94a3b8;margin-top:6px">Ye aapka access token hai — safe rakhein</div>
      <div class="token" id="tokBox">—</div>
      <div class="creds">Order: <span id="credO">—</span></div>
      <div class="warn">⏳ <b>Please wait — Admin Approval Pending</b><br/>Aapka payment admin ke paas verify ke liye chala gaya. Approve hone ke baad aapka ye token automatically activate ho jayega aur aap apne Gmail account se login karke saare features use kar payenge.<br/>Support: <a href="${esc(CFG.TG_LINK)}" target="_blank" style="color:#22d3ee">@BRONX_ULTRA</a></div>
      <a class="btn" href="/login" style="margin-top:16px;width:100%">🔐 SIGN IN WITH GMAIL</a>
    </div>
  </div>

  <div class="section">
    <h2>⭐ WHY BRONX ULTRA</h2>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-top:8px">
      <div style="padding:14px;border-radius:10px;background:rgba(34,211,238,.05);border:1px solid rgba(34,211,238,.3)"><div style="font-size:20px">♾️</div><b style="font-size:13px;color:#22d3ee">Unlimited OSINT</b><div style="font-size:11px;color:#94a3b8;margin-top:4px">All features</div></div>
      <div style="padding:14px;border-radius:10px;background:rgba(34,197,94,.05);border:1px solid rgba(34,197,94,.3)"><div style="font-size:20px">⚡</div><b style="font-size:13px;color:#22c55e">Fast Response</b><div style="font-size:11px;color:#94a3b8;margin-top:4px">High speed servers</div></div>
      <div style="padding:14px;border-radius:10px;background:rgba(234,179,8,.05);border:1px solid rgba(234,179,8,.3)"><div style="font-size:20px">🕐</div><b style="font-size:13px;color:#eab308">24/7 Working</b><div style="font-size:11px;color:#94a3b8;margin-top:4px">Always online</div></div>
      <div style="padding:14px;border-radius:10px;background:rgba(168,85,247,.05);border:1px solid rgba(168,85,247,.3)"><div style="font-size:20px">💬</div><b style="font-size:13px;color:#a855f7">24/7 Support</b><div style="font-size:11px;color:#94a3b8;margin-top:4px">@BRONX_ULTRA</div></div>
    </div>
  </div>
</div>

<footer>© BRONX ULTRA · @BRONX_ULTRA · SECURE PAYMENT</footer>

${BROADCAST_JS}
<script>
var PLANS = [];
var UPI = ${JSON.stringify(CFG.UPI_ID)};
var UPI_NAME = ${JSON.stringify(CFG.UPI_NAME)};
var selected = null;
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
loadBroadcast();
async function loadPlans(){
  try{ var r=await fetch('/api/plans'); var j=await r.json(); PLANS=j.plans||[]; }catch(e){ PLANS=[]; }
  render();
}
function render(){
  var h='';
  for (var i=0;i<PLANS.length;i++){
    var p = PLANS[i];
    h += '<div class="plan '+(p.popular?'popular':'')+'" onclick="selectPlan(\\''+esc(p.id)+'\\')">'
      + '<div class="days">'+esc(p.label)+'</div>'
      + '<div class="price">₹'+p.price+'</div>'
      + '<div class="tag">'+esc(p.tag||'')+'</div>'
      + '<button class="btn gd buy">SELECT</button>'
      + '</div>';
  }
  document.getElementById('plans').innerHTML = h;
}
function selectPlan(id){
  selected = PLANS.find(function(p){return p.id===id;});
  if (!selected) return;
  document.getElementById('selectedPlan').innerHTML = '✅ Selected: <b>'+esc(selected.label)+'</b> · ₹'+selected.price;
  var amt = selected.price;
  var upi = encodeURIComponent(UPI), nm = encodeURIComponent(UPI_NAME);
  var tn = encodeURIComponent('Bronx Ultra '+selected.label);
  document.getElementById('payAny').href     = 'upi://pay?pa='+upi+'&pn='+nm+'&am='+amt+'&cu=INR&tn='+tn;
  document.getElementById('payGpay').href    = 'tez://upi/pay?pa='+upi+'&pn='+nm+'&am='+amt+'&cu=INR&tn='+tn;
  document.getElementById('payPhonepe').href = 'phonepe://pay?pa='+upi+'&pn='+nm+'&am='+amt+'&cu=INR&tn='+tn;
  document.getElementById('payPaytm').href   = 'paytmmp://pay?pa='+upi+'&pn='+nm+'&am='+amt+'&cu=INR&tn='+tn;
  document.getElementById('payBhim').href    = 'upi://pay?pa='+upi+'&pn='+nm+'&am='+amt+'&cu=INR&tn='+tn;
}
function copyUPI(){
  navigator.clipboard.writeText(UPI).then(function(){
    var el=document.getElementById('upiVal'); var o=el.textContent;
    el.textContent='✓ Copied!'; setTimeout(function(){el.textContent=o;},1200);
  });
}
function msg(id, text, type){
  var el=document.getElementById(id); el.textContent=text; el.className='msg '+(type||'ok');
  setTimeout(function(){ el.className='msg'; }, 4000);
}
async function submitPayment(){
  var utr=document.getElementById('utr').value.trim();
  var tg=document.getElementById('tg').value.trim();
  var email=document.getElementById('email').value.trim().toLowerCase();
  if (!selected){ msg('pMsg','❌ Pehle plan select karein','err'); return; }
  if (!utr||utr.length<6){ msg('pMsg','❌ UTR valid daalein (min 6 char)','err'); return; }
  if (!email){ msg('pMsg','❌ Gmail required','err'); return; }
  if (!/^[a-z0-9._%+-]+@gmail\\.com$/.test(email)){ msg('pMsg','❌ Sirf @gmail.com allowed','err'); return; }
  if (!tg){ msg('pMsg','❌ Telegram username/chat id required','err'); return; }
  try{
    var fp = await getFP();
    var r = await fetch('/api/payment/submit', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ planId:selected.id, utr:utr, tg:tg, email:email, fp:fp, ua:navigator.userAgent, device: navigator.platform||'unknown' })
    });
    var j = await r.json();
    if (j.ok){
      document.getElementById('tokBox').textContent = j.token;
      document.getElementById('credO').textContent = j.orderId;
      document.getElementById('success').classList.add('show');
      document.getElementById('success').scrollIntoView({behavior:'smooth'});
      msg('pMsg','✓ Submitted!','ok');
    } else msg('pMsg','❌ '+(j.error||'failed'),'err');
  }catch(e){ msg('pMsg','❌ '+e.message,'err'); }
}
async function getFP(){
  try{
    var d=[navigator.userAgent,navigator.language,screen.width+'x'+screen.height,screen.colorDepth,new Date().getTimezoneOffset(),navigator.hardwareConcurrency||0,navigator.platform||''].join('|');
    var b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(d));
    return Array.from(new Uint8Array(b)).map(function(x){return x.toString(16).padStart(2,'0');}).join('');
  }catch(e){
    var x=localStorage.getItem('bx_fp'); if(!x){ x='fp-'+Math.random().toString(36).slice(2)+Date.now(); localStorage.setItem('bx_fp',x);} return x;
  }
}
loadPlans();
</script></body></html>`;

/* ============================================================
   HTML · ADMIN LOGIN
   ============================================================ */
const ADMIN_LOGIN = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>BRONX · Admin</title>
<style>
${CSS}
</style></head><body>
<div class="center"><div class="box" style="border-color:rgba(34,211,238,.5);box-shadow:0 0 60px rgba(34,211,238,.35)">
  <div class="logo" style="background:linear-gradient(135deg,rgba(34,211,238,.7),#000);border-color:rgba(34,211,238,.9)">⚙</div>
  <h1><span style="color:#22d3ee">BRONX</span> ADMIN</h1>
  <div class="sub" style="color:#a855f7">@BRONX_ULTRA · CONTROL</div>
  <label>USERNAME</label>
  <input id="u"/>
  <label>PASSWORD</label>
  <input id="p" type="password"/>
  <button class="btn" style="width:100%;margin-top:14px" onclick="doLogin()">LOGIN</button>
  <div class="err" id="err"></div>
</div></div>
<script>
async function doLogin(){
  var u=document.getElementById('u').value.trim(), p=document.getElementById('p').value, e=document.getElementById('err');
  e.classList.remove('show');
  if (!u||!p){ e.textContent='Missing credentials'; e.classList.add('show'); return; }
  try{
    var r=await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({u:u,p:p})});
    var j=await r.json();
    if (j.ok){ location.href='/admin'; return; }
    e.textContent=j.error||'Login failed'; e.classList.add('show');
  }catch(ex){ e.textContent=ex.message; e.classList.add('show'); }
}
document.addEventListener('keydown',function(e){ if(e.key==='Enter')doLogin(); });
</script></body></html>`;

/* ============================================================
   HTML · ADMIN PANEL
   ============================================================ */
const ADMIN_HTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>BRONX · Admin Panel</title>
<style>
${CSS}
.wrap{position:relative;z-index:1;max-width:1400px;margin:0 auto;padding:16px}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:14px 18px;background:rgba(0,0,0,.5);border:1px solid rgba(34,211,238,.35);border-radius:14px;margin-bottom:16px}
.brand{display:flex;align-items:center;gap:10px}
.logo2{width:42px;height:42px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(135deg,rgba(34,211,238,.6),#000);border:1px solid rgba(34,211,238,.8);font-size:20px}
h1{font-size:20px;letter-spacing:.15em;font-weight:900}
h1 span{color:#22d3ee}
.sub2{font-size:10px;letter-spacing:.35em;color:#a855f7;margin-top:2px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.stat{padding:16px;background:linear-gradient(180deg,rgba(14,27,42,.72),rgba(8,18,31,.5));border:1px solid rgba(34,211,238,.25);border-radius:14px}
.stat .lbl{font-size:10px;letter-spacing:.28em;color:#94a3b8;font-weight:700}
.stat .val{font-size:24px;font-weight:900;margin-top:6px;color:#22d3ee}
.tabs{display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap}
.tab{padding:10px 14px;font-size:11px;letter-spacing:.18em;font-weight:800;border-radius:8px;cursor:pointer;background:rgba(0,0,0,.4);border:1px solid rgba(255,255,255,.1);color:#94a3b8;font-family:inherit}
.tab.on{background:rgba(34,211,238,.12);border-color:#22d3ee;color:#22d3ee}
.card{padding:20px;background:linear-gradient(180deg,rgba(14,27,42,.72),rgba(8,18,31,.5));border:1px solid rgba(255,255,255,.08);border-radius:16px;margin-bottom:16px}
.card h2{font-size:13px;letter-spacing:.2em;font-weight:800;color:#22d3ee;margin-bottom:14px}
.grid2{display:grid;grid-template-columns:1fr;gap:16px}
@media(min-width:900px){.grid2{grid-template-columns:1fr 1fr}}
.utable{width:100%;border-collapse:collapse;font-size:12px}
.utable th,.utable td{padding:10px 8px;text-align:left;border-bottom:1px solid rgba(255,255,255,.06);vertical-align:top}
.utable th{font-size:10px;letter-spacing:.2em;color:#22d3ee;font-weight:800;text-transform:uppercase}
.utable tr:hover td{background:rgba(34,211,238,.03)}
.pill{display:inline-block;padding:3px 8px;border-radius:999px;font-size:10px;letter-spacing:.1em;font-weight:700;text-transform:uppercase}
.pill.on{background:rgba(34,197,94,.12);color:#86efac;border:1px solid rgba(34,197,94,.5)}
.pill.off{background:rgba(255,46,99,.1);color:#ffb0c4;border:1px solid rgba(255,46,99,.5)}
.pill.exp{background:rgba(234,179,8,.1);color:#fcd34d;border:1px solid rgba(234,179,8,.5)}
.pill.pend{background:rgba(34,211,238,.1);color:#7fefff;border:1px solid rgba(34,211,238,.5)}
.tblwrap{overflow-x:auto}
.act{padding:5px 9px;font-size:10px;letter-spacing:.14em;font-weight:700;border-radius:6px;cursor:pointer;margin-right:4px;margin-top:2px;background:transparent;border:1px solid rgba(255,255,255,.2);color:#fff;font-family:inherit}
.act.red{color:#ffb0c4;border-color:rgba(255,46,99,.5)}
.act.gr{color:#86efac;border-color:rgba(34,197,94,.5)}
.act.gd{color:#fcd34d;border-color:rgba(234,179,8,.5)}
.mono{font-family:ui-monospace,monospace;font-size:11px;color:#7fefff}
.empty{text-align:center;padding:30px;color:#94a3b8;font-size:12px}
.feat-row{display:grid;grid-template-columns:60px 1fr 1fr 2fr 1fr auto;gap:8px;align-items:center;padding:10px;border-bottom:1px solid rgba(255,255,255,.06);font-size:12px}
.feat-row input{padding:8px;font-size:12px}
.plan-row{display:grid;grid-template-columns:90px 70px 80px 1fr auto auto;gap:8px;align-items:center;padding:10px;border-bottom:1px solid rgba(255,255,255,.06);font-size:12px}
.plan-row input{padding:8px;font-size:12px}
.plan-row input[type=number]{width:70px}
@media(max-width:900px){.feat-row,.plan-row{grid-template-columns:1fr;gap:6px}}
</style></head><body>
<div class="wrap">
  <header>
    <div class="brand">
      <div class="logo2">⚙</div>
      <div><h1><span>BRONX</span> ADMIN</h1><div class="sub2">@BRONX_ULTRA · v5.5</div></div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <span class="chip" id="kvChip">KV: --</span>
      <a class="chip" href="/" target="_blank">🌐 APP</a>
      <button class="chip red" onclick="logout()">⏻ LOGOUT</button>
    </div>
  </header>

  <div class="stats">
    <div class="stat"><div class="lbl">TOTAL USERS</div><div class="val" id="stUsers">0</div></div>
    <div class="stat"><div class="lbl">PENDING</div><div class="val" id="stPend" style="color:#eab308">0</div></div>
    <div class="stat"><div class="lbl">ACTIVE TOKENS</div><div class="val" id="stTokens" style="color:#22c55e">0</div></div>
    <div class="stat"><div class="lbl">SESSIONS</div><div class="val" id="stSess">0</div></div>
    <div class="stat"><div class="lbl">STORAGE</div><div class="val" id="stStore" style="font-size:13px;color:#a855f7">--</div></div>
  </div>

  <div class="tabs">
    <button class="tab on" data-tab="pay" onclick="showTab('pay')">💳 PAYMENTS (<span id="pendCount">0</span>)</button>
    <button class="tab" data-tab="tokens" onclick="showTab('tokens')">🎫 TOKENS</button>
    <button class="tab" data-tab="users" onclick="showTab('users')">👥 USERS</button>
    <button class="tab" data-tab="features" onclick="showTab('features')">⚙ FEATURES</button>
    <button class="tab" data-tab="plans" onclick="showTab('plans')">💰 PLANS</button>
    <button class="tab" data-tab="broadcast" onclick="showTab('broadcast')">📢 BROADCAST</button>
    <button class="tab" data-tab="settings" onclick="showTab('settings')">🛠 SETTINGS</button>
  </div>

  <div id="panePay">
    <div class="card"><h2>💳 PENDING REQUESTS</h2><div id="payList"><div class="empty">Loading...</div></div></div>
    <div class="card"><h2>✅ PROCESSED</h2><div id="payHist"><div class="empty">Loading...</div></div></div>
  </div>

  <div id="paneTokens" style="display:none">
    <div class="card"><h2>🎫 ALL TOKENS</h2>
      <div class="tblwrap"><table class="utable">
        <thead><tr><th>TOKEN</th><th>EMAIL</th><th>PLAN</th><th>EXPIRY</th><th>STATUS</th><th>USES</th><th>ACTIONS</th></tr></thead>
        <tbody id="tokBody"><tr><td colspan="7" class="empty">Loading...</td></tr></tbody>
      </table></div>
    </div>
  </div>

  <div id="paneUsers" style="display:none">
    <div class="card"><h2>👥 ALL USERS</h2>
      <div class="tblwrap"><table class="utable">
        <thead><tr><th>EMAIL</th><th>NAME</th><th>STATUS</th><th>TOKEN</th><th>EXPIRY</th><th>DEVICES</th><th>ACTIONS</th></tr></thead>
        <tbody id="uBody"><tr><td colspan="7" class="empty">Loading...</td></tr></tbody>
      </table></div>
    </div>
  </div>

  <div id="paneFeatures" style="display:none">
    <div class="card">
      <h2>⚙ MANAGE FEATURES</h2>
      <p style="font-size:11px;color:#94a3b8;margin-bottom:12px">API key env me set hai — frontend pe expose nahi hoti. Feature ka name, endpoint, param, emoji, color sab yahan change karo.</p>
      <div id="featList"></div>
      <button class="btn gr" style="margin-top:14px" onclick="addFeature()">+ ADD FEATURE</button>
      <button class="btn" style="margin-top:14px" onclick="saveFeatures()">💾 SAVE ALL</button>
    </div>
  </div>

  <div id="panePlans" style="display:none">
    <div class="card">
      <h2>💰 MANAGE PLANS</h2>
      <p style="font-size:11px;color:#94a3b8;margin-bottom:12px">Price, days, label, tag — sab dynamically change karo.</p>
      <div id="planList"></div>
      <button class="btn gr" style="margin-top:14px" onclick="addPlan()">+ ADD PLAN</button>
      <button class="btn" style="margin-top:14px" onclick="savePlans()">💾 SAVE ALL</button>
    </div>
  </div>

  <div id="paneBroadcast" style="display:none">
    <div class="card">
      <h2>📢 BROADCAST MESSAGE</h2>
      <p style="font-size:11px;color:#94a3b8;margin-bottom:12px">Ye message har page pe (login, landing, dashboard) top banner me dikhega.</p>
      <label>MESSAGE (blank = off)</label>
      <textarea id="bcMsg" rows="3" placeholder="e.g. 🎉 20% OFF today only!"></textarea>
      <button class="btn gr" style="margin-top:14px" onclick="saveBroadcast()">📤 BROADCAST NOW</button>
      <button class="btn red" style="margin-top:14px" onclick="clearBroadcast()">🗑 CLEAR</button>
      <div class="msg" id="bcStat"></div>
    </div>
  </div>

  <div id="paneSettings" style="display:none">
    <div class="grid2">
      <div class="card">
        <h2>🔐 CHANGE ADMIN PASSWORD</h2>
        <label>NEW PASSWORD</label><input id="apP" type="password"/>
        <button class="btn" style="margin-top:14px" onclick="changeAdminPass()">UPDATE</button>
        <div class="msg" id="apMsg"></div>
      </div>
      <div class="card">
        <h2>⚠ DANGER ZONE</h2>
        <button class="btn red" onclick="killAllSessions()">KILL ALL SESSIONS</button>
      </div>
    </div>
  </div>
</div>

<script>
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function money(n){ return '₹'+Number(n||0).toLocaleString('en-IN'); }
function fmtDate(t){ if(!t)return '—'; try{ return new Date(t).toLocaleString(); }catch(e){ return t; } }

var FEATURES=[], PLANS=[], USERS=[], TOKENS=[];

function showTab(t){
  ['pay','tokens','users','features','plans','broadcast','settings'].forEach(function(x){
    var p = document.getElementById('pane'+(x.charAt(0).toUpperCase()+x.slice(1)));
    if (p) p.style.display = (x===t)?'block':'none';
  });
  var tabs = document.querySelectorAll('.tab');
  for (var i=0;i<tabs.length;i++) tabs[i].classList.toggle('on', tabs[i].dataset.tab===t);
  if (t==='features') loadFeatures();
  if (t==='plans') loadPlans();
  if (t==='broadcast') loadBroadcast();
  if (t==='tokens') loadTokens();
}

async function loadStats(){
  try{
    var r=await fetch('/api/admin/stats'); var j=await r.json();
    if (!j.ok) return;
    document.getElementById('stUsers').textContent = j.users;
    document.getElementById('stPend').textContent = j.pending||0;
    document.getElementById('pendCount').textContent = j.pending||0;
    document.getElementById('stTokens').textContent = j.activeTokens||0;
    document.getElementById('stSess').textContent = j.sessions;
    document.getElementById('stStore').textContent = j.hasKV?'REDIS':'MEMORY';
    document.getElementById('kvChip').textContent = 'KV: '+(j.hasKV?'ACTIVE':'NONE');
    document.getElementById('kvChip').style.color = j.hasKV?'#22c55e':'#ef2b3a';
  }catch(e){}
}

async function loadPayments(){
  try{
    var r=await fetch('/api/admin/payments'); var j=await r.json();
    if (!j.ok) return;
    renderPays(j.pending||[]);
    renderHist(j.processed||[]);
  }catch(e){}
}
function renderPays(list){
  var el=document.getElementById('payList');
  if (!list.length){ el.innerHTML='<div class="empty">🎉 No pending</div>'; return; }
  var h='';
  for (var i=0;i<list.length;i++){
    var p=list[i];
    h+='<div style="padding:14px;border-radius:12px;background:rgba(234,179,8,.05);border:1px solid rgba(234,179,8,.35);margin-bottom:10px">'
      + '<div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px"><div><b style="color:#eab308;font-size:12px">'+esc(p.planLabel)+' · '+p.days+'d</b><div style="font-size:18px;font-weight:900">'+money(p.price)+'</div></div><span class="pill pend">PENDING</span></div>'
      + '<div class="mono" style="margin-top:6px">UTR: '+esc(p.utr)+'</div>'
      + '<div class="mono">TOKEN: <b style="color:#7fefff">'+esc(p.token||'—')+'</b></div>'
      + '<div style="font-size:11px;color:#94a3b8;margin-top:6px;line-height:1.6">'
        + '📧 Email: '+esc(p.email||'—')+'<br/>'
        + '👤 TG: '+esc(p.tg||'—')+'<br/>'
        + '🆔 Order: '+esc(p.orderId)+'<br/>'
        + '📱 Device: '+esc(p.device||'—')+'<br/>'
        + '🌐 IP: '+esc(p.ip||'—')+'<br/>'
        + '🔒 FP: <span class="mono">'+esc((p.fp||'').slice(0,20))+'…</span><br/>'
        + '🕐 '+fmtDate(p.createdAt)
      + '</div>'
      + '<div style="margin-top:10px">'
        + '<button class="act gr" onclick="approvePay(\\''+esc(p.orderId)+'\\')">✅ APPROVE</button>'
        + '<button class="act red" onclick="rejectPay(\\''+esc(p.orderId)+'\\')">❌ REJECT</button>'
        + '<button class="act" onclick="copyText(\\''+esc(p.token||'')+'\\')">📋 COPY TOKEN</button>'
      + '</div>'
      + '</div>';
  }
  el.innerHTML=h;
}
function renderHist(list){
  var el=document.getElementById('payHist');
  if (!list.length){ el.innerHTML='<div class="empty">No processed</div>'; return; }
  var h='';
  for (var i=0;i<list.length;i++){
    var p=list[i];
    var pill = p.status==='approved'?'<span class="pill on">APPROVED</span>':'<span class="pill off">REJECTED</span>';
    h+='<div style="padding:10px;border-radius:10px;background:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.06);margin-bottom:6px;opacity:.85">'
      + '<div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px"><div><b>'+esc(p.planLabel)+'</b> · '+money(p.price)+' · <span class="mono">'+esc(p.token||'—')+'</span></div>'+pill+'</div>'
      + '<div style="font-size:11px;color:#94a3b8;margin-top:4px">'+esc(p.email||'—')+' · TG: '+esc(p.tg||'—')+' · '+fmtDate(p.processedAt)+'</div>'
      + '</div>';
  }
  el.innerHTML=h;
}
async function approvePay(id){
  if (!confirm('Approve '+id+'?')) return;
  try{
    var r=await fetch('/api/admin/payments/approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({orderId:id})});
    var j=await r.json();
    if (j.ok){ alert('✓ Approved'); loadPayments(); loadStats(); loadUsers(); loadTokens(); }
    else alert('✗ '+(j.error||'failed'));
  }catch(e){ alert(e.message); }
}
async function rejectPay(id){
  var reason=prompt('Reason?','Invalid UTR'); if (reason===null) return;
  try{
    var r=await fetch('/api/admin/payments/reject',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({orderId:id,reason:reason})});
    var j=await r.json();
    if (j.ok){ alert('✓ Rejected'); loadPayments(); loadStats(); }
  }catch(e){ alert(e.message); }
}
function copyText(t){ navigator.clipboard.writeText(t).then(function(){ alert('Copied: '+t); }); }

async function loadTokens(){
  try{
    var r=await fetch('/api/admin/tokens'); var j=await r.json();
    if (!j.ok) return;
    TOKENS=j.tokens||[];
    renderTokens();
  }catch(e){}
}
function renderTokens(){
  var tb=document.getElementById('tokBody');
  if (!TOKENS.length){ tb.innerHTML='<tr><td colspan="7" class="empty">No tokens yet</td></tr>'; return; }
  var now=Date.now(), h='';
  for (var i=0;i<TOKENS.length;i++){
    var t=TOKENS[i];
    var expired = t.expiry && now > new Date(t.expiry).getTime();
    var pill = expired?'<span class="pill exp">EXPIRED</span>':(t.active?'<span class="pill on">ACTIVE</span>':'<span class="pill pend">PENDING</span>');
    h+='<tr>'
      + '<td class="mono">'+esc(t.token)+'</td>'
      + '<td>'+esc(t.email||'—')+'</td>'
      + '<td>'+esc(t.planLabel||'—')+'</td>'
      + '<td class="mono">'+(t.expiry?new Date(t.expiry).toLocaleDateString():'—')+'</td>'
      + '<td>'+pill+'</td>'
      + '<td>'+esc(t.uses||0)+'</td>'
      + '<td>'
        + '<button class="act gd" onclick="extendToken(\\''+esc(t.token)+'\\')">EXTEND</button>'
        + '<button class="act red" onclick="deleteToken(\\''+esc(t.token)+'\\')">DEL</button>'
      + '</td>'
      + '</tr>';
  }
  tb.innerHTML=h;
}
async function extendToken(tk){
  var days=prompt('Extend by how many days?','30'); if (!days) return;
  try{
    var r=await fetch('/api/admin/tokens/extend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:tk,days:parseInt(days)})});
    var j=await r.json(); if (j.ok) loadTokens();
  }catch(e){}
}
async function deleteToken(tk){
  if (!confirm('Delete token '+tk+'?')) return;
  try{
    var r=await fetch('/api/admin/tokens/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:tk})});
    var j=await r.json(); if (j.ok) loadTokens();
  }catch(e){}
}

async function loadUsers(){
  try{
    var r=await fetch('/api/admin/users'); var j=await r.json();
    if (!j.ok) return;
    USERS=j.users||[]; renderUsers();
  }catch(e){}
}
function renderUsers(){
  var tb=document.getElementById('uBody');
  if (!USERS.length){ tb.innerHTML='<tr><td colspan="7" class="empty">No users</td></tr>'; return; }
  var now=Date.now(), h='';
  for (var i=0;i<USERS.length;i++){
    var u=USERS[i];
    var expired = u.expiry && now > new Date(u.expiry).getTime();
    var pill = u.banned?'<span class="pill off">BANNED</span>':(u.accessActive?'<span class="pill on">ACTIVE</span>':(expired?'<span class="pill exp">EXPIRED</span>':'<span class="pill pend">NO ACCESS</span>'));
    h+='<tr>'
      + '<td>'+esc(u.email)+'</td>'
      + '<td>'+esc(u.name||'—')+'</td>'
      + '<td>'+pill+'</td>'
      + '<td class="mono">'+esc(u.token||'—')+'</td>'
      + '<td class="mono">'+(u.expiry?new Date(u.expiry).toLocaleDateString():'—')+'</td>'
      + '<td>'+(u.devices||[]).length+'</td>'
      + '<td>'
        + '<button class="act gd" onclick="editUser(\\''+esc(u.id)+'\\')">EDIT</button>'
        + '<button class="act gr" onclick="resetDevices(\\''+esc(u.id)+'\\')">RESET DEV</button>'
        + '<button class="act '+(u.banned?'gr':'red')+'" onclick="toggleBan(\\''+esc(u.id)+'\\','+(u.banned?'false':'true')+')">'+(u.banned?'UNBAN':'BAN')+'</button>'
        + '<button class="act red" onclick="delUser(\\''+esc(u.id)+'\\')">DEL</button>'
      + '</td>'
      + '</tr>';
  }
  tb.innerHTML=h;
}
async function editUser(id){
  var u=USERS.find(function(x){return x.id===id;}); if (!u) return;
  var exp=prompt('Expiry (YYYY-MM-DD, blank=none):', u.expiry?u.expiry.slice(0,10):''); if (exp===null) return;
  var tk=prompt('Token:', u.token||''); if (tk===null) return;
  var act=confirm('Access active? OK=Yes / Cancel=No');
  try{
    var r=await fetch('/api/admin/users/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,expiry:exp||null,token:tk,accessActive:act})});
    var j=await r.json(); if (j.ok){ loadUsers(); loadTokens(); }
  }catch(e){}
}
async function resetDevices(id){
  if (!confirm('Reset devices?')) return;
  try{
    var r=await fetch('/api/admin/users/devices/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})});
    var j=await r.json(); if (j.ok){ loadUsers(); }
  }catch(e){}
}
async function toggleBan(id,ban){
  try{
    var r=await fetch('/api/admin/users/ban',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,ban:ban})});
    var j=await r.json(); if (j.ok){ loadUsers(); }
  }catch(e){}
}
async function delUser(id){
  if (!confirm('DELETE user?')) return;
  try{
    var r=await fetch('/api/admin/users/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})});
    var j=await r.json(); if (j.ok){ loadUsers(); loadStats(); }
  }catch(e){}
}

async function loadFeatures(){
  try{
    var r=await fetch('/api/admin/features'); var j=await r.json();
    if (j.ok){ FEATURES=j.features||[]; renderFeatures(); }
  }catch(e){}
}
function renderFeatures(){
  var el=document.getElementById('featList');
  if (!FEATURES.length){ el.innerHTML='<div class="empty">No features</div>'; return; }
  var h='';
  for (var i=0;i<FEATURES.length;i++){
    var f=FEATURES[i];
    h+='<div class="feat-row">'
      + '<input value="'+esc(f.emoji||'')+'" data-i="'+i+'" data-k="emoji" placeholder="emoji"/>'
      + '<input value="'+esc(f.name||'')+'" data-i="'+i+'" data-k="name" placeholder="Name"/>'
      + '<input value="'+esc(f.color||'#22d3ee')+'" data-i="'+i+'" data-k="color" placeholder="color"/>'
      + '<input value="'+esc(f.endpoint||'')+'" data-i="'+i+'" data-k="endpoint" placeholder="/api/key-bronx/xxx"/>'
      + '<input value="'+esc(f.param||'num')+'" data-i="'+i+'" data-k="param" placeholder="param"/>'
      + '<button class="act red" onclick="removeFeature('+i+')">DEL</button>'
      + '</div>';
  }
  el.innerHTML=h;
  el.querySelectorAll('input').forEach(function(inp){
    inp.addEventListener('input', function(){
      var i=parseInt(inp.dataset.i), k=inp.dataset.k;
      FEATURES[i][k] = inp.value;
    });
  });
}
function addFeature(){
  FEATURES.push({ id:'feat_'+Date.now(), name:'New Feature', emoji:'🔍', color:'#22d3ee', hint:'Enter value', placeholder:'value', endpoint:'/api/key-bronx/xxx', param:'num', type:'text' });
  renderFeatures();
}
function removeFeature(i){ FEATURES.splice(i,1); renderFeatures(); }
async function saveFeatures(){
  try{
    var r=await fetch('/api/admin/features/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({features:FEATURES})});
    var j=await r.json(); alert(j.ok?'✓ Saved':'✗ Failed');
  }catch(e){ alert(e.message); }
}

async function loadPlans(){
  try{
    var r=await fetch('/api/admin/plans'); var j=await r.json();
    if (j.ok){ PLANS=j.plans||[]; renderPlans(); }
  }catch(e){}
}
function renderPlans(){
  var el=document.getElementById('planList');
  if (!PLANS.length){ el.innerHTML='<div class="empty">No plans</div>'; return; }
  var h='';
  for (var i=0;i<PLANS.length;i++){
    var p=PLANS[i];
    h+='<div class="plan-row">'
      + '<input value="'+esc(p.label||'')+'" data-i="'+i+'" data-k="label" placeholder="Label"/>'
      + '<input type="number" value="'+(p.days||0)+'" data-i="'+i+'" data-k="days" placeholder="days"/>'
      + '<input type="number" value="'+(p.price||0)+'" data-i="'+i+'" data-k="price" placeholder="₹"/>'
      + '<input value="'+esc(p.tag||'')+'" data-i="'+i+'" data-k="tag" placeholder="Tag"/>'
      + '<label style="display:flex;align-items:center;gap:6px;margin:0;font-size:11px;color:#94a3b8"><input type="checkbox" '+(p.popular?'checked':'')+' data-i="'+i+'" data-k="popular" style="width:auto"/> POPULAR</label>'
      + '<button class="act red" onclick="removePlan('+i+')">DEL</button>'
      + '</div>';
  }
  el.innerHTML=h;
  el.querySelectorAll('input').forEach(function(inp){
    inp.addEventListener('change', function(){
      var i=parseInt(inp.dataset.i), k=inp.dataset.k;
      if (inp.type==='checkbox') PLANS[i][k] = inp.checked;
      else if (inp.type==='number') PLANS[i][k] = Number(inp.value);
      else PLANS[i][k] = inp.value;
    });
  });
}
function addPlan(){
  PLANS.push({ id:'p_'+Date.now(), label:'New Plan', days:1, price:100, tag:'', popular:false });
  renderPlans();
}
function removePlan(i){ PLANS.splice(i,1); renderPlans(); }
async function savePlans(){
  try{
    var r=await fetch('/api/admin/plans/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({plans:PLANS})});
    var j=await r.json(); alert(j.ok?'✓ Saved':'✗ Failed');
  }catch(e){ alert(e.message); }
}

async function loadBroadcast(){
  try{
    var r=await fetch('/api/admin/broadcast'); var j=await r.json();
    if (j.ok){ document.getElementById('bcMsg').value = j.message||''; }
  }catch(e){}
}
async function saveBroadcast(){
  var msg = document.getElementById('bcMsg').value.trim();
  try{
    var r=await fetch('/api/admin/broadcast',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg,active:!!msg})});
    var j=await r.json();
    msg2(j.ok?'✓ Broadcast live':'✗ Failed', j.ok?'ok':'err');
  }catch(e){ msg2(e.message,'err'); }
}
async function clearBroadcast(){
  await fetch('/api/admin/broadcast',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:'',active:false})});
  document.getElementById('bcMsg').value='';
  msg2('✓ Cleared','ok');
}
function msg2(t,type){ var e=document.getElementById('bcStat'); e.textContent=t; e.className='msg '+(type||'ok'); setTimeout(function(){ e.className='msg'; },2500); }
function msg(id,t,type){ var e=document.getElementById(id); e.textContent=t; e.className='msg '+(type||'ok'); setTimeout(function(){ e.className='msg'; },3500); }

async function changeAdminPass(){
  var np=document.getElementById('apP').value; if (!np) return;
  try{
    var r=await fetch('/api/admin/change-pass',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({newPass:np})});
    var j=await r.json();
    msg('apMsg', j.ok?'✓ Updated':'✗ Failed', j.ok?'ok':'err');
    if (j.ok) document.getElementById('apP').value='';
  }catch(e){ msg('apMsg',e.message,'err'); }
}
async function killAllSessions(){
  if (!confirm('Kill ALL sessions?')) return;
  try{
    var r=await fetch('/api/admin/kill-sessions',{method:'POST'}); var j=await r.json();
    if (j.ok) alert('✓ Done');
  }catch(e){}
}
async function logout(){ await fetch('/api/logout',{method:'POST'}); location.href='/login'; }

loadStats(); loadPayments(); loadUsers();
setInterval(function(){ loadStats(); loadPayments(); }, 20000);
</script></body></html>`;

/* ============================================================
   ROUTES
   ============================================================ */
app.get('/', async (req, res) => {
  const s = await getSession(req);
  if (s && s.role === 'user') return res.send(DASHBOARD_HTML);
  if (s && s.role === 'admin') return res.redirect('/admin');
  res.send(LANDING_HTML);
});
app.get('/login', async (req, res) => {
  const s = await getSession(req);
  if (s) return res.redirect('/');
  res.send(LOGIN_HTML);
});
app.get('/payment', (req, res) => res.send(PAYMENT_HTML));
app.get('/admin', async (req, res) => {
  const s = await getSession(req);
  if (!s || s.role !== 'admin') return res.send(ADMIN_LOGIN);
  res.send(ADMIN_HTML);
});

/* ============================================================
   PUBLIC CONFIG
   ============================================================ */
app.get('/api/features', async (req, res) => {
  const f = await getFeatures();
  res.json({ features: f.map(function(x){
    return { id:x.id, name:x.name, emoji:x.emoji, color:x.color, hint:x.hint, placeholder:x.placeholder, type:x.type, upper:x.upper, len:x.len };
  })});
});
app.get('/api/plans', async (req, res) => {
  const p = await getPlans();
  res.json({ plans: p });
});
app.get('/api/broadcast', async (req, res) => {
  const b = await kvGet('config:broadcast');
  res.json(b || { message:'', active:false });
});

/* ============================================================
   GOOGLE AUTH
   ============================================================ */
app.post('/api/auth/google', async (req, res) => {
  const b = req.body || {};
  const credential = String(b.credential||'');
  const fp = String(b.fp||'');
  const ua = String(b.ua||'');
  const device = deviceName(ua);
  const ip = clientIP(req);

  if (!credential) return res.status(400).json({ ok:false, error:'Missing credential' });
  if (!CFG.GOOGLE_CID) return res.status(500).json({ ok:false, error:'Google OAuth not configured' });

  let payload;
  try{
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: CFG.GOOGLE_CID });
    payload = ticket.getPayload();
  }catch(e){
    return res.status(401).json({ ok:false, error:'Invalid Google token' });
  }
  if (!payload || !payload.email) return res.status(401).json({ ok:false, error:'Invalid Google payload' });
  if (!isGmail(payload.email)) return res.status(403).json({ ok:false, error:'Sirf @gmail.com allowed' });

  const uid = emailToUid(payload.email);
  let user = await kvGet('user:' + uid);
  if (!user){
    user = {
      id: uid,
      email: String(payload.email).toLowerCase(),
      name: payload.name || '',
      picture: payload.picture || '',
      authMethod: 'google',
      token: '', expiry: null, accessActive: false, pending: false, banned: false,
      devices: [], usage: {}, createdAt: Date.now(), lastLoginAt: Date.now()
    };
    await kvSet('user:' + uid, user);
  } else {
    user.lastLoginAt = Date.now();
    user.name = payload.name || user.name;
    user.picture = payload.picture || user.picture;
    user.authMethod = user.authMethod || 'google';
  }
  await attachDevice(user, uid, fp, ip, device, ua);
  const t = await createSession(user.email, 'user', { uid: uid, fp: fp }, 86400*30);
  setCookie(res, CFG.COOKIE, t, 86400*30);
  res.json({ ok:true, role:'user' });
});

/* ============================================================
   GMAIL + PASSWORD AUTH
   ============================================================ */
app.post('/api/auth/gmail/register', async (req, res) => {
  const b = req.body || {};
  const email = String(b.email||'').trim().toLowerCase();
  const password = String(b.password||'');
  const name = String(b.name||'').trim();
  const fp = String(b.fp||'');
  const ua = String(b.ua||'');
  const device = deviceName(ua);
  const ip = clientIP(req);

  if (!email || !password) return res.status(400).json({ ok:false, error:'Email aur password required' });
  if (!isGmail(email)) return res.status(403).json({ ok:false, error:'Sirf @gmail.com allowed' });
  if (password.length < 6) return res.status(400).json({ ok:false, error:'Password min 6 chars' });

  const uid = emailToUid(email);
  const existing = await kvGet('user:' + uid);
  if (existing && existing.password) return res.status(400).json({ ok:false, error:'Ye Gmail already registered. Login karein.' });
  if (existing && !existing.password){
    /* Account was created via Google — let user set password now */
    existing.password = hashPass(password);
    existing.authMethod = 'hybrid';
    existing.name = name || existing.name;
    existing.lastLoginAt = Date.now();
    await kvSet('user:' + uid, existing);
    await attachDevice(existing, uid, fp, ip, device, ua);
    const t = await createSession(existing.email, 'user', { uid: uid, fp: fp }, 86400*30);
    setCookie(res, CFG.COOKIE, t, 86400*30);
    return res.json({ ok:true, linked:true });
  }

  const user = {
    id: uid, email, name, password: hashPass(password),
    authMethod: 'gmail', token: '', expiry: null, accessActive: false,
    pending: false, banned: false,
    devices: [], usage: {}, createdAt: Date.now(), lastLoginAt: Date.now()
  };
  await attachDevice(user, uid, fp, ip, device, ua);
  await kvSet('user:' + uid, user);
  const t = await createSession(email, 'user', { uid: uid, fp: fp }, 86400*30);
  setCookie(res, CFG.COOKIE, t, 86400*30);
  res.json({ ok:true });
});

app.post('/api/auth/gmail/login', async (req, res) => {
  const b = req.body || {};
  const email = String(b.email||'').trim().toLowerCase();
  const password = String(b.password||'');
  const fp = String(b.fp||'');
  const ua = String(b.ua||'');
  const device = deviceName(ua);
  const ip = clientIP(req);

  if (!email || !password) return res.status(400).json({ ok:false, error:'Email aur password required' });
  if (!isGmail(email)) return res.status(403).json({ ok:false, error:'Sirf @gmail.com allowed' });

  const uid = emailToUid(email);
  const user = await kvGet('user:' + uid);
  if (!user) return res.status(401).json({ ok:false, error:'Account nahi mila. Pehle register karein.' });
  if (user.banned) return res.status(403).json({ ok:false, error:'Account banned' });
  if (!user.password) return res.status(400).json({ ok:false, error:'Ye account Google se bana hai. Google login use karein.' });
  if (!verifyPass(password, user.password)) return res.status(401).json({ ok:false, error:'Password galat' });

  user.lastLoginAt = Date.now();
  await attachDevice(user, uid, fp, ip, device, ua);
  const t = await createSession(email, 'user', { uid: uid, fp: fp }, 86400*30);
  setCookie(res, CFG.COOKIE, t, 86400*30);
  res.json({ ok:true });
});

async function attachDevice(user, uid, fp, ip, device, ua){
  user.devices = user.devices || [];
  const existing = user.devices.find(d => d.fp === fp);
  if (existing){
    existing.lastSeen = Date.now();
    existing.ip = ip;
  } else {
    user.devices.push({ fp: fp, ip: ip, device: device, ua: String(ua).slice(0,200), added: Date.now(), lastSeen: Date.now() });
    if (user.devices.length > 5) user.devices = user.devices.slice(-5);
  }
  await kvSet('user:' + uid, user);
}

/* ============================================================
   ADMIN AUTH
   ============================================================ */
app.post('/api/admin/login', async (req, res) => {
  const b = req.body || {};
  const u = String(b.u||'').trim().toLowerCase();
  const p = String(b.p||'');
  const ac = await adminCreds();
  if (u === String(ac.u).toLowerCase() && verifyPass(p, ac.p)){
    const t = await createSession('admin', 'admin', {}, 86400*7);
    setCookie(res, CFG.COOKIE, t, 86400*7);
    return res.json({ ok:true, role:'admin' });
  }
  res.status(401).json({ ok:false, error:'Invalid admin credentials' });
});

app.post('/api/logout', async (req, res) => {
  const s = await getSession(req);
  if (s) await kvDel('sess:' + s.token);
  clearCookie(res, CFG.COOKIE);
  res.json({ ok:true });
});

/* ============================================================
   USER APIs
   ============================================================ */
app.get('/api/me', async (req, res) => {
  const s = await getSession(req);
  if (!s) return res.status(401).json({ ok:false });
  if (s.role === 'admin') return res.json({ ok:true, role:'admin', email:'admin' });
  const u = await kvGet('user:' + s.uid);
  if (!u) return res.status(401).json({ ok:false });
  const expired = u.expiry && Date.now() > new Date(u.expiry).getTime();
  res.json({
    ok:true, role:'user',
    email: u.email, name: u.name,
    token: u.token, expiry: u.expiry,
    accessActive: u.accessActive && !expired
  });
});

app.get('/api/account/info', async (req, res) => {
  const s = await getSession(req);
  if (!s || s.role !== 'user') return res.status(401).json({ ok:false });
  const u = await kvGet('user:' + s.uid);
  if (!u) return res.status(401).json({ ok:false });
  const expired = u.expiry && Date.now() > new Date(u.expiry).getTime();
  res.json({
    ok:true,
    user: {
      email: u.email, name: u.name, picture: u.picture,
      token: u.token, expiry: u.expiry,
      accessActive: u.accessActive && !expired,
      devices: u.devices||[],
      createdAt: u.createdAt
    },
    usage: u.usage || {}
  });
});

/* ============================================================
   LOOKUP PROXY — API key NEVER exposed
   ============================================================ */
app.get('/api/lookup', async (req, res) => {
  const s = await getSession(req);
  if (!s || s.role !== 'user') return res.status(401).json({ error:'Session expired' });

  const u = await kvGet('user:' + s.uid);
  if (!u) return res.status(401).json({ error:'User not found' });
  if (u.banned) return res.status(403).json({ error:'Banned' });
  const expired = u.expiry && Date.now() > new Date(u.expiry).getTime();
  if (!u.accessActive || expired) return res.status(402).json({ error:'No active access' });

  const featureId = String(req.query.feature||'');
  const q = String(req.query.q||'');
  if (!featureId || !q) return res.status(400).json({ error:'Missing params' });

  const features = await getFeatures();
  const feat = features.find(f => f.id === featureId);
  if (!feat) return res.status(404).json({ error:'Feature not found' });

  const param = feat.param || 'num';
  const url = CFG.BASE + feat.endpoint + '?key=' + encodeURIComponent(CFG.KEY) + '&' + param + '=' + encodeURIComponent(q);

  try{
    const r = await fetch(url, { headers:{ 'User-Agent':'BronxUltra/5.5' }});
    const txt = await r.text();
    let parsed;
    try{ parsed = JSON.parse(txt); }
    catch(e){ return res.status(502).json({ error:'Invalid upstream JSON', raw: txt.slice(0,400) }); }

    u.usage = u.usage || {};
    u.usage[feat.name] = (u.usage[feat.name] || 0) + 1;
    u.lastUsedAt = Date.now();
    await kvSet('user:' + s.uid, u);

    res.json(parsed);
  }catch(e){
    res.status(502).json({ error:'Upstream failed: ' + e.message });
  }
});

/* ============================================================
   PAYMENT
   ============================================================ */
app.post('/api/payment/submit', async (req, res) => {
  const b = req.body || {};
  const plans = await getPlans();
  const plan = plans.find(p => p.id === b.planId);
  if (!plan) return res.status(400).json({ ok:false, error:'Invalid plan' });
  const utr = String(b.utr||'').trim();
  const tg = String(b.tg||'').trim();
  const email = String(b.email||'').trim().toLowerCase();
  if (!utr || utr.length < 6) return res.status(400).json({ ok:false, error:'Invalid UTR' });
  if (!isGmail(email)) return res.status(403).json({ ok:false, error:'Sirf @gmail.com allowed' });
  if (!tg) return res.status(400).json({ ok:false, error:'Telegram required' });

  const existing = await kvGet('pay_utr:' + utr);
  if (existing) return res.status(400).json({ ok:false, error:'UTR already submitted' });

  const orderId = randOrderId();
  const token = randToken();

  const payObj = {
    orderId, token,
    planId: plan.id, planLabel: plan.label, days: plan.days, price: plan.price,
    utr, tg, email,
    fp: String(b.fp||''), ua: String(b.ua||''), device: String(b.device||''),
    ip: clientIP(req), status:'pending', createdAt: Date.now()
  };
  await kvSet('payment:' + orderId, payObj);
  await kvSet('pay_utr:' + utr, orderId);
  await kvSet('token:' + token, {
    token, orderId, email, planLabel: plan.label, days: plan.days,
    expiry: null, active: false, uses: 0, createdAt: Date.now()
  });

  res.json({ ok:true, token, orderId });
});

/* ============================================================
   ADMIN APIs
   ============================================================ */
const adminAuth = async (req, res, next) => {
  const s = await getSession(req);
  if (!s || s.role !== 'admin') return res.status(401).json({ ok:false, error:'Admin auth required' });
  next();
};

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  const uk = await kvKeys('user:');
  const sk = await kvKeys('sess:');
  const pk = await kvKeys('payment:');
  const tk = await kvKeys('token:');
  let pending = 0, activeTokens = 0;
  for (const k of pk){
    const p = await kvGet(k);
    if (p && p.status === 'pending') pending++;
  }
  for (const k of tk){
    const t = await kvGet(k);
    if (t && t.active && (!t.expiry || Date.now() < new Date(t.expiry).getTime())) activeTokens++;
  }
  res.json({ ok:true, users:uk.length, sessions:sk.length, pending, activeTokens, hasKV:!!(CFG.KV_URL&&CFG.KV_TOKEN) });
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  const keys = await kvKeys('user:');
  const users = [];
  for (const k of keys){
    const u = await kvGet(k);
    if (u){
      const expired = u.expiry && Date.now() > new Date(u.expiry).getTime();
      users.push({
        id: u.id, email: u.email, name: u.name, token: u.token || '',
        expiry: u.expiry || null, accessActive: u.accessActive && !expired,
        banned: !!u.banned, devices: u.devices || [], usage: u.usage || {},
        createdAt: u.createdAt, lastLoginAt: u.lastLoginAt,
        authMethod: u.authMethod || 'unknown'
      });
    }
  }
  users.sort((a,b) => (b.createdAt||0) - (a.createdAt||0));
  res.json({ ok:true, users });
});

app.post('/api/admin/users/update', adminAuth, async (req, res) => {
  const b = req.body || {};
  const u = await kvGet('user:' + b.id);
  if (!u) return res.status(404).json({ ok:false, error:'Not found' });
  if ('expiry' in b) u.expiry = b.expiry || null;
  if ('token' in b) u.token = String(b.token||'');
  if ('accessActive' in b) u.accessActive = !!b.accessActive;
  await kvSet('user:' + b.id, u);
  res.json({ ok:true });
});

app.post('/api/admin/users/devices/reset', adminAuth, async (req, res) => {
  const b = req.body || {};
  const u = await kvGet('user:' + b.id);
  if (!u) return res.status(404).json({ ok:false, error:'Not found' });
  u.devices = [];
  await kvSet('user:' + b.id, u);
  res.json({ ok:true });
});

app.post('/api/admin/users/ban', adminAuth, async (req, res) => {
  const b = req.body || {};
  const u = await kvGet('user:' + b.id);
  if (!u) return res.status(404).json({ ok:false, error:'Not found' });
  u.banned = !!b.ban;
  await kvSet('user:' + b.id, u);
  res.json({ ok:true });
});

app.post('/api/admin/users/delete', adminAuth, async (req, res) => {
  const b = req.body || {};
  await kvDel('user:' + b.id);
  res.json({ ok:true });
});

app.get('/api/admin/payments', adminAuth, async (req, res) => {
  const keys = await kvKeys('payment:');
  const all = [];
  for (const k of keys){
    const p = await kvGet(k);
    if (p) all.push(p);
  }
  all.sort((a,b) => (b.createdAt||0) - (a.createdAt||0));
  const pending = all.filter(p => p.status === 'pending');
  const processed = all.filter(p => p.status !== 'pending').slice(0, 50);
  res.json({ ok:true, pending, processed });
});

app.post('/api/admin/payments/approve', adminAuth, async (req, res) => {
  const b = req.body || {};
  const p = await kvGet('payment:' + b.orderId);
  if (!p) return res.status(404).json({ ok:false, error:'Not found' });
  if (p.status === 'approved') return res.json({ ok:true, already:true });

  const expiryIso = new Date(Date.now() + p.days * 86400000).toISOString();

  /* Update token */
  const tk = await kvGet('token:' + p.token);
  if (tk){
    tk.active = true;
    tk.expiry = expiryIso;
    tk.approvedAt = Date.now();
    await kvSet('token:' + p.token, tk);
  }

  /* Activate the matching user (by email) */
  const uid = emailToUid(p.email);
  let u = await kvGet('user:' + uid);
  if (!u){
    /* Auto-create user account with the payment email */
    u = {
      id: uid, email: p.email, name:'', password: null,
      authMethod: 'payment',
      token: p.token, expiry: expiryIso, accessActive: true,
      pending: false, banned: false,
      devices: p.fp ? [{ fp: p.fp, ip: p.ip||'', device: p.device||'', ua: p.ua||'', added: Date.now(), lastSeen: Date.now() }] : [],
      usage: {}, createdAt: Date.now(), lastLoginAt: Date.now()
    };
    await kvSet('user:' + uid, u);
  } else {
    u.token = p.token;
    u.expiry = expiryIso;
    u.accessActive = true;
    u.pending = false;
    if (p.fp && !u.devices.some(d => d.fp === p.fp)){
      u.devices.push({ fp: p.fp, ip: p.ip||'', device: p.device||'', ua: p.ua||'', added: Date.now(), lastSeen: Date.now() });
    }
    await kvSet('user:' + uid, u);
  }

  p.status = 'approved';
  p.processedAt = Date.now();
  await kvSet('payment:' + b.orderId, p);
  res.json({ ok:true });
});

app.post('/api/admin/payments/reject', adminAuth, async (req, res) => {
  const b = req.body || {};
  const p = await kvGet('payment:' + b.orderId);
  if (!p) return res.status(404).json({ ok:false, error:'Not found' });
  p.status = 'rejected';
  p.reason = String(b.reason||'');
  p.processedAt = Date.now();
  await kvSet('payment:' + b.orderId, p);
  await kvDel('pay_utr:' + p.utr);
  await kvDel('token:' + p.token);
  res.json({ ok:true });
});

/* TOKENS */
app.get('/api/admin/tokens', adminAuth, async (req, res) => {
  const keys = await kvKeys('token:');
  const tokens = [];
  for (const k of keys){
    const t = await kvGet(k);
    if (t) tokens.push(t);
  }
  tokens.sort((a,b) => (b.createdAt||0) - (a.createdAt||0));
  res.json({ ok:true, tokens });
});

app.post('/api/admin/tokens/extend', adminAuth, async (req, res) => {
  const b = req.body || {};
  const tk = await kvGet('token:' + b.token);
  if (!tk) return res.status(404).json({ ok:false, error:'Not found' });
  const days = Number(b.days||0);
  if (!days) return res.status(400).json({ ok:false, error:'Days required' });
  const current = tk.expiry ? new Date(tk.expiry).getTime() : Date.now();
  tk.expiry = new Date(current + days*86400000).toISOString();
  tk.active = true;
  await kvSet('token:' + b.token, tk);
  /* Sync to user too */
  if (tk.email){
    const uid = emailToUid(tk.email);
    const u = await kvGet('user:' + uid);
    if (u){ u.expiry = tk.expiry; u.accessActive = true; await kvSet('user:' + uid, u); }
  }
  res.json({ ok:true });
});

app.post('/api/admin/tokens/delete', adminAuth, async (req, res) => {
  const b = req.body || {};
  await kvDel('token:' + b.token);
  res.json({ ok:true });
});

/* FEATURES */
app.get('/api/admin/features', adminAuth, async (req, res) => {
  const f = await getFeatures();
  res.json({ ok:true, features: f });
});
app.post('/api/admin/features/save', adminAuth, async (req, res) => {
  const b = req.body || {};
  if (!Array.isArray(b.features)) return res.status(400).json({ ok:false, error:'Invalid' });
  await kvSet('config:features', b.features);
  res.json({ ok:true });
});

/* PLANS */
app.get('/api/admin/plans', adminAuth, async (req, res) => {
  const p = await getPlans();
  res.json({ ok:true, plans: p });
});
app.post('/api/admin/plans/save', adminAuth, async (req, res) => {
  const b = req.body || {};
  if (!Array.isArray(b.plans)) return res.status(400).json({ ok:false, error:'Invalid' });
  await kvSet('config:plans', b.plans);
  res.json({ ok:true });
});

/* BROADCAST */
app.get('/api/admin/broadcast', adminAuth, async (req, res) => {
  const b = await kvGet('config:broadcast');
  res.json({ ok:true, message:(b&&b.message)||'', active:!!(b&&b.active) });
});
app.post('/api/admin/broadcast', adminAuth, async (req, res) => {
  const b = req.body || {};
  await kvSet('config:broadcast', { message:String(b.message||''), active:!!b.active });
  res.json({ ok:true });
});

/* SETTINGS */
app.post('/api/admin/change-pass', adminAuth, async (req, res) => {
  const np = String((req.body||{}).newPass||'');
  if (!np) return res.status(400).json({ ok:false, error:'Required' });
  await kvSet('admin:creds', { u: CFG.ADMIN_U, p: hashPass(np) });
  res.json({ ok:true });
});
app.post('/api/admin/kill-sessions', adminAuth, async (req, res) => {
  const keys = await kvKeys('sess:');
  for (const k of keys) await kvDel(k);
  clearCookie(res, CFG.COOKIE);
  res.json({ ok:true, killed: keys.length });
});

/* ============================================================
   404 + START
   ============================================================ */
app.use((req, res) => res.status(404).send('404 · BRONX ULTRA'));

app.listen(CFG.PORT, () => {
  console.log('════════════════════════════════════════════════════');
  console.log('  BRONX ULTRA v5.5 · @BRONX_ULTRA');
  console.log('  Port: ' + CFG.PORT);
  console.log('  Google OAuth: ' + (CFG.GOOGLE_CID ? 'CONFIGURED' : 'NOT SET'));
  console.log('  Storage: ' + ((CFG.KV_URL && CFG.KV_TOKEN) ? 'UPSTASH REDIS' : 'IN-MEMORY (temporary!)'));
  console.log('  UPI: ' + CFG.UPI_ID);
  console.log('════════════════════════════════════════════════════');
});
