
/**
 * FreeSite SaaS — Master Server (Security Hardened + Dynamic Domain /myshop Router + Glassmorphism UI)
 * Architect: Sojib | WhatsApp: 01409084819 | TikTok: @sojib..music
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const pino = require('pino');
const { GoogleGenAI } = require('@google/genai');

const { pool, initializeDatabase } = require('./database');
const { initializeProductCloudSystem } = require('./product_cloud_db');
const { analyzeAndExtractWebsiteKnowledge } = require('./website_analyzer');
const apiV1Router = require('./api_v1_router');
const {
  getActiveGenAIClient,
  rotateToNextApiKey,
  trackTokenUsage,
  tokenStats,
  parseBudgetFromText,
  searchSmartProducts,
  transcribeAudioWithGemini,
  callGeminiUltraFast,
  GEMINI_MODEL,
  GEMINI_FALLBACK_MODELS
} = require('./ai_engine');

const {
  default: makeWASocket,
  DisconnectReason,
  fetchLatestBaileysVersion,
  downloadMediaMessage,
  delay,
  initAuthCreds,
  BufferJSON
} = require('@whiskeysockets/baileys');

const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1);
app.disable('x-powered-by');

// ================= SECURITY HELPERS =================
function escapeHtml(unsafe) {
  if (unsafe === null || unsafe === undefined) return '';
  return String(unsafe)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function sanitizeUrl(url) {
  if (!url) return '';
  const trimmed = String(url).trim();
  if (/^(https?:\/\/|\/)/i.test(trimmed)) return trimmed;
  return '';
}

function safeCompare(a, b) {
  const bufA = Buffer.from(String(a || ''), 'utf8');
  const bufB = Buffer.from(String(b || ''), 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const [salt, key] = String(stored || '').split(':');
    if (!salt || !key) return false;
    const keyBuf = Buffer.from(key, 'hex');
    const derived = crypto.scryptSync(String(password), salt, 64);
    if (keyBuf.length !== derived.length) return false;
    return crypto.timingSafeEqual(keyBuf, derived);
  } catch (e) {
    return false;
  }
}

function getAuthSecret() {
  return process.env.SESSION_SECRET || process.env.ADMIN_PASSWORD || 'freesite_sojib_secret_key_2026';
}

function signUserToken(payload) {
  const data = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 7 * 86400 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', getAuthSecret()).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyUserToken(token) {
  try {
    const [data, sig] = String(token || '').split('.');
    if (!data || !sig) return null;
    const expected = crypto.createHmac('sha256', getAuthSecret()).update(data).digest('base64url');
    if (!safeCompare(sig, expected)) return null;
    const parsed = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (!parsed.exp || parsed.exp < Date.now()) return null;
    return parsed;
  } catch (e) {
    return null;
  }
}

function getLoggedInUser(req) {
  const raw = req.headers.cookie || '';
  const match = raw.match(/freesite_user_auth=([^;]+)/);
  if (!match) return null;
  return verifyUserToken(decodeURIComponent(match[1]));
}

function setUserAuthCookie(req, res, payload) {
  const token = signUserToken(payload);
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';
  const flags = [
    `freesite_user_auth=${encodeURIComponent(token)}`,
    'Path=/',
    'Max-Age=604800',
    'HttpOnly',
    'SameSite=Lax'
  ];
  if (isHttps) flags.push('Secure');
  res.setHeader('Set-Cookie', flags.join('; '));
}

function requireUserAuth(req, res, next) {
  const user = getLoggedInUser(req);
  if (!user) {
    return res.status(401).json({ success: false, message: '🔒 অনুগ্রহ করে প্রথমে আপনার অ্যাকাউন্টে লগইন বা রেজিস্টার করুন।' });
  }
  req.authUser = user;
  next();
}

async function isSuperAdminCookie(req) {
  try {
    const cookiePass = parseAdminCookie(req);
    if (!cookiePass) return false;
    const masterPassword = await getMasterAdminPassword();
    return safeCompare(cookiePass.trim(), masterPassword);
  } catch (e) {
    return false;
  }
}

async function requireBotOwner(req, res, next) {
  try {
    const user = getLoggedInUser(req);
    const isAdmin = await isSuperAdminCookie(req);
    if (!user && !isAdmin) {
      return res.status(401).json({ success: false, message: '🔒 অনুগ্রহ করে প্রথমে লগইন করুন!' });
    }
    const botId = Number(req.body?.botId || req.query?.botId);
    if (!botId) {
      return res.status(400).json({ success: false, message: 'বট আইডি পাওয়া যায়নি।' });
    }
    const botRes = await pool.query('SELECT id, user_id FROM whatsapp_bots WHERE id = $1', [botId]);
    if (botRes.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'বট পাওয়া যায়নি।' });
    }
    const bot = botRes.rows[0];
    if (!isAdmin && (!bot.user_id || bot.user_id !== user.id)) {
      return res.status(403).json({ success: false, message: '⛔ এই শপ/বটটি আপনার অ্যাকাউন্টের নয়!' });
    }
    req.authUser = user;
    next();
  } catch (e) {
    res.status(500).json({ success: false, message: 'Auth check error' });
  }
}

function generateLoginRequiredPage(titleText = 'লগইন প্রয়োজন') {
  return `<!DOCTYPE html>
<html lang="bn">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>${escapeHtml(titleText)} — FreeSite AI</title>
  <link href="https://fonts.googleapis.com/css2?family=Hind+Siliguri:wght@500;600;700&family=Noto+Sans+Bengali:wght@600;700;800&display=swap" rel="stylesheet">
  <style>
    *{box-sizing:border-box;margin:0;padding:0;font-family:'Hind Siliguri','Noto Sans Bengali',sans-serif}
    body{background:#f1f5f9;background-image:radial-gradient(at 0% 0%,rgba(16,185,129,.09) 0,transparent 50%),radial-gradient(at 100% 100%,rgba(14,165,233,.08) 0,transparent 50%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:18px;color:#0f172a;font-weight:600;line-height:1.65}
    .card{max-width:420px;width:100%;background:rgba(255,255,255,.82);backdrop-filter:blur(18px);border:1px solid #fff;border-radius:22px;padding:28px 24px;box-shadow:0 16px 40px rgba(15,23,42,.08);text-align:center}
    h2{font-size:21px;font-weight:800;color:#065f46;margin-bottom:6px;padding-top:2px}
    p{font-size:13.5px;color:#475569;margin-bottom:18px}
    input{width:100%;padding:12px 14px;border-radius:12px;border:1px solid #cbd5e1;margin-bottom:12px;font-size:14.5px;font-weight:600;outline:none}
    input:focus{border-color:#059669;box-shadow:0 0 0 4px rgba(16,185,129,.15)}
    button{width:100%;padding:13px;background:linear-gradient(135deg,#059669,#047857);color:#fff;border:none;border-radius:12px;font-size:15px;font-weight:800;cursor:pointer}
    .err{color:#b91c1c;font-size:13px;margin-top:10px;display:none;font-weight:700}
    a{display:inline-block;margin-top:14px;color:#059669;font-size:13px;font-weight:800;text-decoration:none}
  </style>
</head>
<body>
  <div class="card">
    <h2>🔒 ${escapeHtml(titleText)}</h2>
    <p>আপনার নিজস্ব ড্যাশবোর্ডে প্রবেশ করতে অনুগ্রহ করে অ্যাকাউন্টে লগইন করুন।</p>
    <input type="email" id="lEmail" placeholder="ইমেইল ঠিকানা">
    <input type="password" id="lPass" placeholder="পাসওয়ার্ড" onkeypress="if(event.key==='Enter') doGateLogin()">
    <button onclick="doGateLogin()">লগইন করুন</button>
    <div id="lErr" class="err"></div>
    <a href="/">নতুন অ্যাকাউন্ট খুলতে হোম পেজে যান 👉</a>
  </div>
  <script>
    async function doGateLogin(){
      const email=document.getElementById('lEmail').value.trim();
      const password=document.getElementById('lPass').value;
      const res=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})});
      const d=await res.json();
      if(d.success)window.location.reload();
      else{const e=document.getElementById('lErr');e.style.display='block';e.textContent=d.message;}
    }
  </script>
</body>
</html>`;
}

// Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate Limiters
const apiGeneralLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 150,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'অনেক বেশি রিকোয়েস্ট পাঠানো হয়েছে। ১ মিনিট পর আবার চেষ্টা করুন।' }
});

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: '🔒 অতিরিক্ত ভুল চেষ্টার কারণে ১৫ মিনিটের জন্য লগইন সাময়িকভাবে লক করা হয়েছে।' }
});

app.use('/api/', apiGeneralLimiter);

// 🌐 Universal Product API v1 মাউন্ট
app.use('/api/v1', apiV1Router);

// 🔄 প্রতিদিন রাত ১২:০০ টায় মেসেজ কাউন্টার ০ করা এবং মেয়াদ শেষ হওয়া বট ফ্রি প্ল্যানে নামিয়ে দেওয়া
setInterval(async () => {
  const now = new Date();
  if (now.getHours() === 0 && now.getMinutes() === 0 && now.getSeconds() < 10) {
    try {
      await pool.query('UPDATE whatsapp_bots SET requests_today = 0');
      await pool.query(`
        UPDATE whatsapp_bots 
        SET plan = 'free', rate_limit_daily = 300, package_name = 'Expired (Free)'
        WHERE expires_at IS NOT NULL AND expires_at < NOW() AND plan != 'free'
      `);
      console.log('[SYSTEM]: 🔄 Daily request limits reset & expired plans downgraded.');
    } catch (e) {
      console.error('[RESET ERROR]:', e.message);
    }
  }
}, 10000);

const activeSockets = new Map();
const botChatHistories = new Map();
const botLiveLogs = new Map();

// ডায়নামিক ডোমেইন ক্যাশ (অ্যাডমিন প্যানেল থেকে যুক্ত ডোমেইনসমূহ)
let cachedActiveDomains = [];
let lastDomainFetch = 0;

async function getActivePlatformDomains() {
  const now = Date.now();
  if (now - lastDomainFetch < 10000 && cachedActiveDomains.length > 0) {
    return cachedActiveDomains;
  }
  try {
    const res = await pool.query('SELECT domain_name FROM platform_domains WHERE is_active = TRUE ORDER BY id ASC');
    cachedActiveDomains = res.rows.map(r => r.domain_name.toLowerCase().trim()).filter(Boolean);
    lastDomainFetch = now;
  } catch (e) {}
  return cachedActiveDomains;
}

function addBotLog(botId, type, message) {
  const bId = Number(botId);
  if (!botLiveLogs.has(bId)) botLiveLogs.set(bId, []);
  const logs = botLiveLogs.get(bId);
  const time = new Date().toLocaleTimeString('en-US', { hour12: false });
  logs.unshift({ time, type, message });
  if (logs.length > 50) logs.pop();
}

// PostgreSQL সেশন অ্যাডাপ্টার
async function usePostgresAuthState(botId) {
  const getSession = async (key) => {
    const res = await pool.query('SELECT session_data FROM whatsapp_sessions WHERE bot_id = $1 AND session_key = $2', [botId, key]);
    if (res.rows.length > 0) return JSON.parse(res.rows[0].session_data, BufferJSON.reviver);
    return null;
  };

  const setSession = async (key, value) => {
    if (value === null || value === undefined) {
      await pool.query('DELETE FROM whatsapp_sessions WHERE bot_id = $1 AND session_key = $2', [botId, key]);
    } else {
      const dataStr = JSON.stringify(value, BufferJSON.replacer);
      await pool.query(
        `INSERT INTO whatsapp_sessions (bot_id, session_key, session_data, updated_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (bot_id, session_key)
         DO UPDATE SET session_data = $3, updated_at = NOW()`,
        [botId, key, dataStr]
      );
    }
  };

  let creds = await getSession('creds');
  if (!creds) {
    creds = initAuthCreds();
    await setSession('creds', creds);
  }

  return {
    state: {
      creds,
      keys: {
        get: async (type, ids) => {
          const data = {};
          for (const id of ids) {
            const val = await getSession(`${type}-${id}`);
            if (val) data[id] = val;
          }
          return data;
        },
        set: async (data) => {
          for (const category in data) {
            for (const id in data[category]) {
              await setSession(`${category}-${id}`, data[category][id]);
            }
          }
        }
      }
    },
    saveCreds: () => setSession('creds', creds)
  };
}

// ================= ১ নম্বর অগ্রাধিকার: ডায়নামিক ডোমেইন ও /myshop রাউটার =================
app.use(async (req, res, next) => {
  const reservedTopPaths = ['/api/', '/admin', '/ping', '/catalog-builder', '/catalog/', '/c/'];
  if (reservedTopPaths.some(p => req.path.startsWith(p) || req.path === p)) {
    return next();
  }

  const rawHost = req.headers['x-forwarded-host'] || req.headers.host || '';
  const host = rawHost.toLowerCase().split(':')[0].trim().replace(/^www\./, '');
  const activeDomains = await getActivePlatformDomains();

  let matchedBaseDomain = activeDomains.find(d => host === d || host.endsWith('.' + d)) || host;

  let detectedSub = req.query.sub ? String(req.query.sub).trim().toLowerCase() : null;
  let detectedBase = matchedBaseDomain || host || 'busness-bot.onrender.com';
  let isDirectShopPath = false;
  let nestedProductId = null;

  // ১. সাবডোমেইন ভিত্তিক ডিটেকশন (যেমন: myshop.yourdomain.com)
  for (const base of activeDomains) {
    if (host.endsWith('.' + base) && host !== base) {
      detectedSub = host.slice(0, -(base.length + 1)).trim().toLowerCase();
      detectedBase = base;
      break;
    }
  }

  // ২. পাথ ভিত্তিক ডিটেকশন (যেমন: yourdomain.com/dash/myshop অথবা yourdomain.com/myshop অথবা yourdomain.com/myshop/p/15)
  const segments = req.path.split('/').filter(Boolean);
  if (segments[0] === 'dash' && segments[1]) {
    detectedSub = segments[1].toLowerCase().trim();
    isDirectShopPath = false;
  } else if (
    segments.length >= 1 &&
    !req.path.includes('.') &&
    !['api', 'dash', 'catalog', 'catalog-builder', 'p', 'c', 'admin', 'ping', 'shop', 'products'].includes(segments[0].toLowerCase())
  ) {
    detectedSub = segments[0].toLowerCase().trim();
    isDirectShopPath = true;
    if (segments[1] === 'p' && segments[2]) {
      nestedProductId = parseInt(segments[2], 10);
    }
  }

  if (detectedSub && !['admin', 'api', 'dashboard', 'mail', 'www', 'favicon'].includes(detectedSub)) {
    try {
      const cleanSub = detectedSub.replace(/[^a-z0-9-]/g, '');
      if (!cleanSub) return next();

      const botRes = await pool.query(
        `SELECT b.*, h.theme_color 
         FROM whatsapp_bots b 
         LEFT JOIN hosted_websites h ON b.id = h.bot_id 
         WHERE LOWER(b.subdomain) = $1 OR LOWER(h.subdomain) = $1 
         ORDER BY b.id DESC LIMIT 1`,
        [cleanSub]
      );

      if (botRes.rows.length > 0) {
        const bot = botRes.rows[0];
        const effectiveDomain = host || bot.base_domain || detectedBase;

        if (req.path === '/catalog-builder' || (isDirectShopPath && segments[1] === 'catalog-builder')) {
          if (!getLoggedInUser(req)) return res.status(401).send(generateLoginRequiredPage('ক্যাটালগ বিল্ডার লক'));
          return res.sendFile(path.join(__dirname, 'public', 'catalog_builder.html'));
        }

        const targetProductId = nestedProductId || (req.path.startsWith('/p/') ? parseInt(req.path.replace('/p/', ''), 10) : null);
        if (targetProductId && !isNaN(targetProductId)) {
          const singleP = await pool.query('SELECT * FROM bot_products WHERE id = $1 AND bot_id = $2', [targetProductId, bot.id]);
          if (singleP.rows.length > 0) {
            return res.send(generateSingleProductPage(bot, singleP.rows[0], effectiveDomain, cleanSub));
          }
        }

        if (
          isDirectShopPath ||
          req.path === '/shop' ||
          req.path === '/catalog' ||
          req.path === '/products'
        ) {
          const prods = await pool.query('SELECT * FROM bot_products WHERE bot_id = $1 ORDER BY id DESC', [bot.id]);
          return res.send(generateStorefrontView(bot, prods.rows, `${effectiveDomain}/${cleanSub}`, cleanSub, effectiveDomain));
        }

        // 🔒 ওনার ড্যাশবোর্ড (/dash/myshop) — অবশ্যই লগইন ও নিজস্ব মালিকানা থাকতে হবে
        const authUser = getLoggedInUser(req);
        const isAdmin = await isSuperAdminCookie(req);
        if (!authUser && !isAdmin) {
          return res.status(401).send(generateLoginRequiredPage('ড্যাশবোর্ড লক'));
        }
        if (!isAdmin && (!bot.user_id || bot.user_id !== authUser.id)) {
          return res.status(403).send(`
            <div style="font-family:'Hind Siliguri',sans-serif;text-align:center;padding:50px;background:#f1f5f9;min-height:100vh;">
              <h2 style="color:#b91c1c;">⛔ অ্যাক্সেস অনুমোদিত নয়!</h2>
              <p style="color:#475569;margin-top:8px;">এই ড্যাশবোর্ডটি আপনার অ্যাকাউন্টের নয়। অনুগ্রহ করে সঠিক অ্যাকাউন্ট দিয়ে লগইন করুন।</p>
              <a href="/" style="display:inline-block;margin-top:16px;background:#059669;color:#fff;padding:10px 22px;border-radius:10px;text-decoration:none;font-weight:700;">হোম পেজে যান</a>
            </div>
          `);
        }

        const pNumRes = await pool.query("SELECT key, value FROM admin_settings WHERE key IN ('bkash_no', 'nagad_no', 'rocket_no')");
        const payConfig = {};
        pNumRes.rows.forEach(r => { payConfig[r.key] = r.value; });

        return res.send(generateUserBrandedDashboard(bot, effectiveDomain, cleanSub, payConfig));
      } else {
        return res.status(404).send(`
          <!DOCTYPE html><html lang="bn"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
          <title>শপ পাওয়া যায়নি</title>
          <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@600;800&family=Hind+Siliguri:wght@600;700&display=swap" rel="stylesheet">
          <style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;background:#f1f5f9;background-image:radial-gradient(at 0% 0%,rgba(16,185,129,.1) 0,transparent 50%);font-family:'Hind Siliguri','Noto Sans Bengali',sans-serif; font-weight:600; line-height:1.65;color:#0f172a}.box{max-width:440px;width:100%;background:rgba(255,255,255,.78);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,.9);border-radius:22px;padding:34px 26px;text-align:center;box-shadow:0 15px 35px rgba(15,23,42,.08)}.btn{display:inline-block;margin-top:18px;background:linear-gradient(135deg,#059669,#047857);color:#fff;padding:12px 24px;border-radius:12px;text-decoration:none;font-weight:700}</style>
          </head><body><div class="box"><h2 style="font-size:22px;margin-bottom:8px;">⚠️ শপ বা ড্যাশবোর্ড পাওয়া যায়নি!</h2><p style="color:#64748b;font-size:14px;"><b>${escapeHtml(cleanSub)}</b> নামে কোনো স্টোর এখনো তৈরি করা হয়নি।</p><a href="/" class="btn">নতুন শপ তৈরি করুন 👉</a></div></body></html>
        `);
      }
    } catch (err) {
      console.error('[ROUTER ERROR]:', err);
    }
  }
  next();
});

// স্ট্যাটিক ফাইল মিডলওয়্যার
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ================= একক পণ্যের গ্লাস কার্ড পেজ জেনারেটর =================
function generateSingleProductPage(bot, p, domain, slug) {
  const primaryColor = /^#[0-9a-fA-F]{3,6}$/.test(bot.theme_color || '') ? bot.theme_color : '#059669';
  const discount = p.regular_price && Number(p.regular_price) > Number(p.price)
    ? Math.round(((Number(p.regular_price) - Number(p.price)) / Number(p.regular_price)) * 100)
    : 0;

  let demoGallery = [];
  if (p.demo_images) {
    try {
      const parsed = JSON.parse(p.demo_images);
      if (Array.isArray(parsed)) demoGallery = parsed;
      else demoGallery = [p.demo_images];
    } catch (e) {
      demoGallery = [p.demo_images];
    }
  }

  const safePhone = String(bot.phone_number || '').replace(/[^0-9]/g, '');
  const waText = encodeURIComponent(`আসসালামু আলাইকুম, আমি এই পণ্যটি অর্ডার করতে চাই:\n📦 পণ্য: ${p.name}\n💰 মূল্য: ৳${p.price}\n🔗 লিংক: https://${domain}/${slug}/p/${p.id}`);

  return `<!DOCTYPE html>
<html lang="bn">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(p.name)} — ${escapeHtml(bot.bot_name)}</title>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=Hind+Siliguri:wght@400;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css">
  <style>
    :root { --primary: ${primaryColor}; }
    * { box-sizing:border-box; margin:0; padding:0; font-family:'Hind Siliguri','Noto Sans Bengali',sans-serif; font-weight:600; line-height:1.65; }
    body {
      background-color:#f1f5f9;
      background-image:
        radial-gradient(at 0% 0%, rgba(16,185,129,0.09) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(14,165,233,0.08) 0px, transparent 50%),
        radial-gradient(at 50% 100%, rgba(99,102,241,0.06) 0px, transparent 50%);
      background-attachment:fixed; color:#0f172a; padding:24px 14px; min-height:100vh; display:flex; justify-content:center; align-items:flex-start;
    }
    .card {
      max-width:520px; width:100%; background:rgba(255,255,255,0.75); backdrop-filter:blur(18px); -webkit-backdrop-filter:blur(18px);
      border:1px solid rgba(255,255,255,0.9); border-radius:24px; overflow:hidden;
      box-shadow:0 20px 50px -10px rgba(15,23,42,0.1);
    }
    .img-wrap { width:100%; height:330px; background:rgba(241,245,249,0.75); position:relative; display:flex; align-items:center; justify-content:center; border-bottom:1px solid rgba(226,232,240,0.8); }
    .img-wrap img { width:100%; height:100%; object-fit:contain; }
    .badge-cat { position:absolute; top:14px; left:14px; background:rgba(15,23,42,0.78); backdrop-filter:blur(8px); color:#fff; font-size:11px; font-weight:700; padding:5px 12px; border-radius:999px; }
    .badge-off { position:absolute; top:14px; right:14px; background:#ef4444; color:#fff; font-size:11px; font-weight:800; padding:5px 11px; border-radius:999px; }
    .body { padding:24px; }
    .store-tag { font-size:12px; color:#64748b; font-weight:700; margin-bottom:6px; display:flex; align-items:center; gap:5px; }
    h1 { font-size:22px; font-weight:800; line-height:1.35; margin-bottom:10px; color:#0f172a; }
    .price-row { display:flex; align-items:baseline; gap:10px; margin-bottom:16px; }
    .curr { font-size:28px; font-weight:800; color:#059669; }
    .reg { font-size:15px; color:#94a3b8; text-decoration:line-through; }
    .desc-box { background:rgba(255,255,255,0.65); border:1px solid rgba(226,232,240,0.8); border-radius:14px; padding:14px; font-size:14px; color:#334155; line-height:1.65; margin-bottom:18px; }
    .demo-wrap { background:rgba(238,242,255,0.7); border:1px solid #c7d2fe; border-radius:16px; padding:14px; margin-bottom:18px; }
    .demo-grid { display:grid; grid-template-columns:repeat(auto-fill, minmax(110px, 1fr)); gap:8px; margin-top:8px; }
    .demo-grid img { width:100%; height:105px; object-fit:cover; border-radius:10px; border:1px solid #e0e7ff; background:#fff; cursor:pointer; }
    .btn-wa {
      display:flex; align-items:center; justify-content:center; gap:8px; width:100%; padding:15px;
      background:linear-gradient(135deg,#059669,#047857); color:#fff; text-decoration:none; border-radius:14px;
      font-size:15px; font-weight:800; box-shadow:0 8px 22px rgba(5,150,105,0.32); transition:.2s;
    }
    .btn-wa:hover { transform:translateY(-1px); }
    .btn-row { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:10px; }
    .btn-sec {
      display:flex; align-items:center; justify-content:center; gap:6px; padding:11px; border-radius:12px;
      background:rgba(255,255,255,0.85); border:1px solid #cbd5e1; color:#334155; font-size:13px; font-weight:700; text-decoration:none; cursor:pointer;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="img-wrap">
      <span class="badge-cat">${escapeHtml(p.category || 'General')}</span>
      ${discount > 0 ? `<span class="badge-off">${discount}% OFF</span>` : ''}
      ${p.image_url ? `<img id="mainPreview" src="${escapeHtml(p.image_url)}" alt="${escapeHtml(p.name)}">` : `<i class="ti ti-photo" style="font-size:64px;color:#cbd5e1;"></i>`}
    </div>
    <div class="body">
      <div class="store-tag"><i class="ti ti-building-store" style="color:#059669;"></i> ${escapeHtml(bot.bot_name)}</div>
      <h1>${escapeHtml(p.name)}</h1>
      <div class="price-row">
        <span class="curr">৳${escapeHtml(p.price)}</span>
        ${p.regular_price && Number(p.regular_price) > Number(p.price) ? `<span class="reg">৳${escapeHtml(p.regular_price)}</span>` : ''}
      </div>
      ${demoGallery.length > 0 ? `
      <div class="demo-wrap">
        <div style="font-size:12px;font-weight:800;color:#3730a3;"><i class="ti ti-photo-star"></i> ডেমো গ্যালারি (${demoGallery.length}টি ছবি):</div>
        <div class="demo-grid">
          ${demoGallery.map(img => `<img src="${escapeHtml(img)}" onclick="var m=document.getElementById('mainPreview');if(m)m.src=this.src;" alt="Demo">`).join('')}
        </div>
      </div>` : ''}
      <div class="desc-box">${escapeHtml(p.description || 'পণ্যটি সম্পর্কে বিস্তারিত জানতে বা অর্ডার করতে নিচের হোয়াটসঅ্যাপ বাটনে ক্লিক করুন।')}</div>
      <a href="https://wa.me/${safePhone}?text=${waText}" target="_blank" class="btn-wa">
        <i class="ti ti-brand-whatsapp" style="font-size:21px;"></i> সরাসরি হোয়াটসঅ্যাপে অর্ডার করুন
      </a>
      <div class="btn-row">
        <button onclick="navigator.clipboard.writeText(location.href);alert('লিংক কপি হয়েছে!');" class="btn-sec"><i class="ti ti-copy"></i> লিংক কপি</button>
        <a href="/${escapeHtml(slug)}" class="btn-sec"><i class="ti ti-arrow-left"></i> সব পণ্য দেখুন</a>
      </div>
    </div>
  </div>
</body>
</html>`;
}

// ================= পাবলিক কাস্টমার স্টোরফ্রন্ট (Frosted Glassmorphism) =================
function generateStorefrontView(bot, products, fullUrl, slug = '', domain = '') {
  const primaryColor = /^#[0-9a-fA-F]{3,6}$/.test(bot.theme_color || '') ? bot.theme_color : '#059669';
  const safePhone = String(bot.phone_number || '').replace(/[^0-9]/g, '');
  const storeSlug = slug || bot.subdomain || bot.catalog_slug || 'shop';
  const storeName = bot.bot_name || bot.store_name || 'Online Store';

  const categories = Array.from(new Set((products || []).map(p => (p.category || 'General').trim()).filter(Boolean)));

  return `<!DOCTYPE html>
<html lang="bn">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(storeName)} — অফিসিয়াল শপ</title>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=Hind+Siliguri:wght@400;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css">
  <style>
    :root {
      --primary: ${primaryColor};
      --text: #0f172a;
      --muted: #64748b;
      --glass-surface: rgba(255, 255, 255, 0.72);
      --glass-border: rgba(255, 255, 255, 0.85);
      --glass-shadow: 0 10px 32px rgba(31, 38, 135, 0.06);
    }
    * { box-sizing:border-box; margin:0; padding:0; font-family:'Hind Siliguri','Noto Sans Bengali',sans-serif; font-weight:600; line-height:1.65; }
    body {
      background-color: #f1f5f9;
      background-image:
        radial-gradient(at 0% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(14, 165, 233, 0.08) 0px, transparent 50%),
        radial-gradient(at 50% 100%, rgba(99, 102, 241, 0.06) 0px, transparent 50%);
      background-attachment: fixed; color: var(--text); padding: 24px 14px; min-height: 100vh;
    }
    .store-container { max-width: 1020px; margin: 0 auto; }

    .glass-header {
      background: rgba(255,255,255,0.75); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--glass-border); border-radius: 22px; padding: 24px 26px;
      margin-bottom: 22px; box-shadow: var(--glass-shadow);
      display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 16px;
    }
    .brand-title { font-size: 24px; font-weight: 800; color: #065f46; display: flex; align-items: center; gap: 10px; line-height: 1.3; }
    .brand-sub { font-size: 13px; color: var(--muted); margin-top: 4px; max-width: 560px; line-height: 1.5; }
    .wa-pill {
      display: inline-flex; align-items: center; gap: 8px;
      background: linear-gradient(135deg, #059669, #047857); color: #fff; text-decoration: none;
      padding: 11px 20px; border-radius: 999px; font-size: 13px; font-weight: 800;
      box-shadow: 0 6px 20px rgba(5,150,105,0.28); transition: .2s; white-space: nowrap;
    }
    .wa-pill:hover { transform: translateY(-1px); }

    .filter-bar {
      background: var(--glass-surface); backdrop-filter: blur(16px);
      border: 1px solid var(--glass-border); border-radius: 18px; padding: 14px;
      margin-bottom: 22px; box-shadow: var(--glass-shadow);
      display: flex; flex-wrap: wrap; gap: 10px; align-items: center; justify-content: space-between;
    }
    .search-input {
      flex: 1; min-width: 210px; padding: 11px 16px; border-radius: 12px;
      background: rgba(255,255,255,0.85); border: 1px solid rgba(203,213,225,0.8);
      font-size: 14px; outline: none; color: #0f172a;
    }
    .search-input:focus { border-color: #059669; box-shadow: 0 0 0 4px rgba(16,185,129,0.15); }
    .cat-pills { display: flex; gap: 6px; overflow-x: auto; padding-bottom: 2px; max-width: 100%; }
    .cat-pill {
      padding: 8px 14px; border-radius: 999px; font-size: 12px; font-weight: 700; cursor: pointer;
      border: 1px solid rgba(226,232,240,0.9); background: rgba(255,255,255,0.75); color: #475569; white-space: nowrap; transition: .2s;
    }
    .cat-pill.active { background: #059669; color: #fff; border-color: #059669; }

    .product-grid {
      display: grid; grid-template-columns: repeat(auto-fill, minmax(235px, 1fr)); gap: 18px; margin-bottom: 30px;
    }
    .prod-card {
      background: var(--glass-surface); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--glass-border); border-radius: 20px; overflow: hidden;
      box-shadow: var(--glass-shadow); display: flex; flex-direction: column; transition: .25s ease;
    }
    .prod-card:hover { transform: translateY(-4px); box-shadow: 0 18px 40px rgba(15,23,42,0.09); }
    .prod-img-box { width: 100%; height: 200px; background: rgba(241,245,249,0.7); display:flex; align-items:center; justify-content:center; position:relative; overflow:hidden; }
    .prod-img-box img { width: 100%; height: 100%; object-fit: cover; }
    .discount-badge { position:absolute; top:10px; left:10px; background:#ef4444; color:#fff; font-size:11px; font-weight:800; padding:4px 10px; border-radius:999px; }
    .prod-body { padding: 18px; flex: 1; display: flex; flex-direction: column; justify-content: space-between; }
    .p-cat { font-size: 11px; background: rgba(236,253,245,0.9); color: #047857; padding: 3px 10px; border-radius: 999px; display: inline-block; margin-bottom: 8px; font-weight: 700; border: 1px solid rgba(167,243,208,0.8); }
    .p-title { font-size: 16px; font-weight: 800; color: #0f172a; margin-bottom: 8px; line-height: 1.4; }
    .price-row { display: flex; align-items: baseline; gap: 8px; margin-bottom: 14px; }
    .curr-price { font-size: 20px; font-weight: 800; color: #059669; }
    .reg-price { font-size: 13px; color: #94a3b8; text-decoration: line-through; }
    .btn-row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
    .view-btn {
      background: rgba(255,255,255,0.85); color: #334155; text-decoration: none; text-align: center;
      padding: 10px; border-radius: 11px; font-size: 12px; font-weight: 700; border: 1px solid rgba(203,213,225,0.8);
    }
    .order-btn {
      background: linear-gradient(135deg, #059669, #047857); color: #fff; text-decoration: none; text-align: center;
      padding: 10px; border-radius: 11px; font-size: 12px; font-weight: 700;
      display: inline-flex; align-items: center; justify-content: center; gap: 5px;
    }
    .empty-glass {
      background: var(--glass-surface); backdrop-filter: blur(16px); border: 1px solid var(--glass-border);
      padding: 46px 20px; text-align: center; border-radius: 22px; color: var(--muted);
    }
  </style>
</head>
<body>
  <div class="store-container">
    <div class="glass-header">
      <div>
        <div class="brand-title"><i class="ti ti-building-store" style="color:#059669;"></i> ${escapeHtml(storeName)}</div>
        <p class="brand-sub">${escapeHtml(bot.system_prompt ? bot.system_prompt.substring(0, 120) : 'আমাদের অফিসিয়াল অনলাইন শপে আপনাকে স্বাগতম! মানসম্মত পণ্য সরাসরি অর্ডার করুন।')}</p>
      </div>
      ${safePhone ? `<a href="https://wa.me/${safePhone}" class="wa-pill" target="_blank"><i class="ti ti-brand-whatsapp" style="font-size:18px;"></i> WhatsApp অর্ডার সাপোর্ট</a>` : ''}
    </div>

    <div class="filter-bar">
      <input type="text" id="shopSearch" class="search-input" placeholder="🔍 পণ্য খুঁজুন (নাম বা ক্যাটাগরি)..." oninput="filterShopProducts()">
      <div class="cat-pills">
        <button class="cat-pill active" onclick="selectCat('ALL', this)">সব পণ্য</button>
        ${categories.map(c => `<button class="cat-pill" onclick="selectCat('${escapeHtml(c)}', this)">${escapeHtml(c)}</button>`).join('')}
      </div>
    </div>

    ${products.length === 0 ? `
    <div class="empty-glass">
      <i class="ti ti-package-off" style="font-size:44px; color:#94a3b8; display:block; margin-bottom:10px;"></i>
      <b style="color:#0f172a; font-size:16px;">বর্তমানে কোনো পণ্য তালিকায় নেই</b>
      <p style="font-size:13px; margin-top:4px;">স্টোর ওনার শীঘ্রই নতুন পণ্য যুক্ত করবেন।</p>
    </div>` : ''}

    <div class="product-grid" id="productGrid">
      ${products.map(p => {
        const discount = p.regular_price && Number(p.regular_price) > Number(p.price)
          ? Math.round(((Number(p.regular_price) - Number(p.price)) / Number(p.regular_price)) * 100)
          : 0;
        const itemDetailUrl = p.id ? `/${escapeHtml(storeSlug)}/p/${p.id}` : '#';
        const waOrderUrl = `https://wa.me/${safePhone}?text=${encodeURIComponent('আমি এই পণ্যটি অর্ডার করতে চাই: ' + p.name + ' (৳' + p.price + ')')}`;
        return `
        <div class="prod-card" data-name="${escapeHtml(String(p.name || '').toLowerCase())}" data-cat="${escapeHtml(String(p.category || 'General'))}">
          <div class="prod-img-box">
            ${discount > 0 ? `<div class="discount-badge">${discount}% OFF</div>` : ''}
            ${p.image_url ? `<img src="${escapeHtml(p.image_url)}" alt="${escapeHtml(p.name)}">` : `<i class="ti ti-photo" style="font-size:44px; color:#cbd5e1;"></i>`}
          </div>
          <div class="prod-body">
            <div>
              <span class="p-cat">${escapeHtml(p.category || 'General')}</span>
              <div class="p-title">${escapeHtml(p.name)}</div>
              <div class="price-row">
                <span class="curr-price">৳${escapeHtml(p.price)}</span>
                ${p.regular_price && Number(p.regular_price) > Number(p.price) ? `<span class="reg-price">৳${escapeHtml(p.regular_price)}</span>` : ''}
              </div>
            </div>
            <div class="btn-row">
              <a href="${itemDetailUrl}" class="view-btn">বিস্তারিত</a>
              <a href="${waOrderUrl}" target="_blank" class="order-btn"><i class="ti ti-brand-whatsapp"></i> অর্ডার</a>
            </div>
          </div>
        </div>`;
      }).join('')}
    </div>

    <div style="text-align:center; padding:18px; font-size:12px; color:var(--muted);">
      Powered by <b>FreeSite AI</b> • Store: <b>${escapeHtml(fullUrl)}</b>
    </div>
  </div>
  <script>
    let activeCat = 'ALL';
    function selectCat(cat, btn) {
      activeCat = cat;
      document.querySelectorAll('.cat-pill').forEach(el => el.classList.remove('active'));
      btn.classList.add('active');
      filterShopProducts();
    }
    function filterShopProducts() {
      const q = (document.getElementById('shopSearch').value || '').toLowerCase().trim();
      document.querySelectorAll('.prod-card').forEach(card => {
        const name = card.getAttribute('data-name') || '';
        const cat = card.getAttribute('data-cat') || '';
        const matchQ = !q || name.includes(q) || cat.toLowerCase().includes(q);
        const matchC = activeCat === 'ALL' || cat === activeCat;
        card.style.display = (matchQ && matchC) ? 'flex' : 'none';
      });
    }
  </script>
</body>
</html>`;
}

// ================= স্টোর ওনার + হোয়াটসঅ্যাপ AI ড্যাশবোর্ড (Frosted Glassmorphism) =================
function generateUserBrandedDashboard(bot, activeDomain, slug, payConfig = {}) {
  const primaryColor = /^#[0-9a-fA-F]{3,6}$/.test(bot.theme_color || '') ? bot.theme_color : '#059669';
  const bkash = escapeHtml(payConfig.bkash_no || '01409084819');
  const nagad = escapeHtml(payConfig.nagad_no || '01409084819');
  const rocket = escapeHtml(payConfig.rocket_no || '01409084819');

  const storePublicUrl = `https://${activeDomain}/${slug}`;
  const dashPublicUrl = `https://${activeDomain}/dash/${slug}`;

  return `<!DOCTYPE html>
<html lang="bn">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(bot.bot_name)} — Control Center</title>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=Hind+Siliguri:wght@400;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css">
  <style>
    :root {
      --primary: ${primaryColor};
      --text: #0f172a;
      --muted: #64748b;
      --glass-surface: rgba(255, 255, 255, 0.72);
      --glass-subtle: rgba(255, 255, 255, 0.62);
      --glass-border: rgba(255, 255, 255, 0.85);
      --glass-shadow: 0 10px 32px rgba(31, 38, 135, 0.06);
    }
    * { box-sizing:border-box; margin:0; padding:0; font-family:'Hind Siliguri','Noto Sans Bengali',sans-serif; font-weight:600; line-height:1.65; }
    body {
      background-color: #f1f5f9;
      background-image:
        radial-gradient(at 0% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(14, 165, 233, 0.08) 0px, transparent 50%),
        radial-gradient(at 50% 100%, rgba(99, 102, 241, 0.06) 0px, transparent 50%);
      background-attachment: fixed; color: var(--text); padding: 20px 14px; min-height: 100vh;
    }
    .container { max-width: 960px; margin: 0 auto; }

    .header {
      background: rgba(255,255,255,0.78); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--glass-border); border-radius: 20px; padding: 20px 24px;
      display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 14px;
      margin-bottom: 20px; box-shadow: var(--glass-shadow);
    }
    .brand-title { font-size: 21px; font-weight: 800; color: #065f46; display: flex; align-items: center; gap: 10px; }
    .status-badge { font-size: 12px; font-weight: 800; padding: 7px 16px; border-radius: 999px; backdrop-filter: blur(8px); }
    .status-badge.connected { background: rgba(220,252,231,0.9); color: #15803d; border: 1px solid #bbf7d0; }
    .status-badge.disconnected { background: rgba(254,226,226,0.9); color: #b91c1c; border: 1px solid #fecaca; }

    .stats-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; margin-bottom: 20px; }
    @media (min-width: 640px) { .stats-grid { grid-template-columns: repeat(4, 1fr); } }
    .stat-box {
      background: var(--glass-subtle); backdrop-filter: blur(14px); border: 1px solid var(--glass-border);
      border-radius: 18px; padding: 18px 14px; text-align: center; box-shadow: 0 4px 16px rgba(15,23,42,0.03);
    }
    .stat-lbl { font-size: 11px; color: var(--muted); font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-val { font-size: 24px; font-weight: 800; color: #059669; margin-top: 6px; }

    .tabs { display: flex; flex-wrap: wrap; gap: 8px; padding-bottom: 6px; margin-bottom: 18px; }
    .tab-btn {
      flex: 1 1 auto; justify-content: center; background: rgba(255,255,255,0.75); color: #475569; border: 1px solid rgba(226,232,240,0.9);
      padding: 10px 14px; border-radius: 999px; font-size: 12.5px; font-weight: 700; cursor: pointer; white-space: nowrap;
      box-shadow: none; display: inline-flex; align-items: center; gap: 6px;
    }
    .tab-btn.active { background: linear-gradient(135deg, #059669, #047857); color: #fff; border-color: transparent; box-shadow: 0 6px 18px rgba(5,150,105,0.28); }

    .card {
      background: var(--glass-surface); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--glass-border); border-radius: 20px; padding: 24px;
      margin-bottom: 20px; box-shadow: var(--glass-shadow); transition: .2s;
    }
    .card h3 { font-size: 17px; font-weight: 800; color: #065f46; display: flex; align-items: center; gap: 8px; margin-bottom: 14px; }

    .form-group { margin-bottom: 16px; }
    label { display: block; font-size: 13px; color: #334155; margin-bottom: 7px; font-weight: 700; }
    input, select, textarea {
      width: 100%; padding: 12px 15px; background: rgba(255,255,255,0.85);
      border: 1px solid rgba(203,213,225,0.85); border-radius: 12px; font-size: 14px; color: #0f172a; outline: none; transition: .2s;
    }
    input:focus, select:focus, textarea:focus { background: #fff; border-color: #059669; box-shadow: 0 0 0 4px rgba(16,185,129,0.15); }

    button.primary-btn {
      width: 100%; padding: 13px 18px; background: linear-gradient(135deg, #059669 0%, #047857 100%);
      color: #fff; border: 1px solid rgba(255,255,255,0.25); border-radius: 12px; font-weight: 800; cursor: pointer;
      display: flex; justify-content: center; align-items: center; gap: 8px; font-size: 14px;
      box-shadow: 0 8px 20px rgba(5,150,105,0.3); transition: .2s;
    }
    button.primary-btn:hover { transform: translateY(-1px); box-shadow: 0 10px 24px rgba(5,150,105,0.4); }

    .code-box {
      background: rgba(240,253,244,0.88); border: 2px dashed #059669; padding: 20px; border-radius: 16px;
      text-align: center; margin-top: 16px; display: none;
    }
    .code-val { font-size: 30px; font-weight: 800; letter-spacing: 7px; color: #047857; font-family: monospace; margin: 8px 0; }

    .terminal-window {
      background: rgba(15,23,42,0.92); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.12);
      border-radius: 16px; padding: 16px; height: 210px; overflow-y: auto; font-family: monospace; font-size: 12.5px; color: #f8fafc;
    }
    .log-time { color: #10b981; font-weight: 700; }
    .log-line { margin-bottom: 6px; line-height: 1.45; }

    .pay-methods { display: flex; gap: 10px; margin-bottom: 14px; }
    .pay-badge {
      flex: 1; text-align: center; padding: 11px; border-radius: 12px; font-size: 13px; font-weight: 700;
      border: 1px solid rgba(203,213,225,0.9); cursor: pointer; background: rgba(255,255,255,0.75); transition: .2s;
    }
    .pay-badge.active { background: rgba(236,253,245,0.95); border-color: #059669; color: #059669; box-shadow: 0 4px 12px rgba(5,150,105,0.14); }
    .color-picker { display: flex; gap: 12px; margin-top: 10px; }
    .color-dot { width: 34px; height: 34px; border-radius: 50%; cursor: pointer; border: 3px solid #fff; box-shadow: 0 4px 10px rgba(0,0,0,0.12); }
    .grid-2 { display: grid; grid-template-columns: 1fr; gap: 12px; }
    @media (min-width: 640px) { .grid-2 { grid-template-columns: 1fr 1fr; } }
  </style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <div class="brand-title"><i class="ti ti-brand-whatsapp" style="color:#059669; font-size:26px;"></i> ${escapeHtml(bot.bot_name)}</div>
      <p style="font-size:12px; color:var(--muted); margin-top:4px;">
        🛍️ শপ লিংক: <a href="${escapeHtml(storePublicUrl)}" target="_blank" style="color:#059669; font-weight:700;">${escapeHtml(storePublicUrl)}</a>
        • প্ল্যান: <b>${escapeHtml((bot.plan || 'free').toUpperCase())}</b>
      </p>
    </div>
    <span class="status-badge ${bot.status === 'CONNECTED' ? 'connected' : 'disconnected'}">
      ● ${escapeHtml(bot.status || 'DISCONNECTED')}
    </span>
  </div>

  <div class="stats-grid">
    <div class="stat-box"><div class="stat-lbl">মোট টোকেন</div><div class="stat-val" id="tokenVal">${Number(bot.tokens_used || 0)}</div></div>
    <div class="stat-box"><div class="stat-lbl">আজকের মেসেজ</div><div class="stat-val" id="reqVal">${Number(bot.requests_today || 0)}</div></div>
    <div class="stat-box"><div class="stat-lbl">ডেইলি লিমিট</div><div class="stat-val" style="color:#d97706;">${Number(bot.rate_limit_daily || 300)}</div></div>
    <div class="stat-box"><div class="stat-lbl">প্যাকেজ</div><div class="stat-val" style="font-size:16px; color:#0284c7;">${escapeHtml(bot.package_name || 'Free Trial')}</div></div>
  </div>

  <div class="tabs">
    <button class="tab-btn active" onclick="switchDashTab('pane-wa', this)"><i class="ti ti-brand-whatsapp"></i> WhatsApp & AI টেস্ট</button>
    <button class="tab-btn" onclick="switchDashTab('pane-products', this)"><i class="ti ti-box"></i> প্রোডাক্ট ও শপ</button>
    <button class="tab-btn" onclick="switchDashTab('pane-settings', this)"><i class="ti ti-settings"></i> এআই সেটিংস ও সাইট</button>
    <button class="tab-btn" onclick="switchDashTab('pane-billing', this)"><i class="ti ti-crown"></i> প্রিমিয়াম ও API Key</button>
  </div>

  <div id="pane-wa" class="dash-pane">
    <div class="card">
      <h3><i class="ti ti-qrcode"></i> WhatsApp লিঙ্ক করুন (Pairing Code)</h3>
      <div class="form-group">
        <label>আপনার মোবাইল নম্বর (যেমন: 88017...):</label>
        <input type="text" id="phoneInput" placeholder="8801XXXXXXXXX" value="${escapeHtml(bot.phone_number || '')}">
      </div>
      <button class="primary-btn" onclick="requestPairingCode(${bot.id})"><i class="ti ti-key"></i> পেয়ারিং কোড তৈরি করুন</button>
      <div id="codeBanner" class="code-box">
        <div style="font-size:12px; color:#047857; font-weight:700;">WHATSAPP PAIRING CODE</div>
        <div id="codeDisplay" class="code-val">----</div>
        <p style="font-size:12px; color:#475569;">WhatsApp ➔ Linked Devices ➔ Link with phone number-এ কোডটি দিন।</p>
      </div>
    </div>

    <div class="card" style="border:1.5px solid rgba(16,185,129,0.5);">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; flex-wrap:wrap; gap:8px;">
        <h3 style="margin:0;"><i class="ti ti-messages"></i> লাইভ এআই টেস্ট চ্যাট</h3>
        <div style="display:flex; gap:6px; align-items:center;">
          <button type="button" onclick="switchDashTab('pane-billing', document.querySelectorAll('.tab-btn')[3])" style="padding:4px 10px; border-radius:999px; background:#fef3c7; color:#b45309; border:1px solid #fde68a; font-size:11px; font-weight:800; cursor:pointer;">🔑 API Key দিন</button>
          <span style="font-size:11px; padding:4px 10px; border-radius:999px; background:#dcfce7; color:#15803d; font-weight:700;">● AI Active</span>
        </div>
      </div>
      <div id="testChatWindow" style="background:rgba(255,255,255,0.8); border:1px solid rgba(203,213,225,0.8); border-radius:14px; padding:14px; height:180px; overflow-y:auto; margin-bottom:10px; font-size:13px;">
        <div style="color:#64748b; font-style:italic;">বটের সাথে কথা বলতে নিচে মেসেজ লিখুন...</div>
      </div>
      <div style="display:flex; gap:8px;">
        <input type="text" id="testMsgInput" onkeypress="if(event.key==='Enter') sendTestChatMessage(${bot.id})" placeholder="যেমন: পণ্যের দাম কত? অথবা হাই..." style="flex:1;">
        <button id="testSendBtn" class="primary-btn" onclick="sendTestChatMessage(${bot.id})" style="width:auto; padding:0 20px;"><i class="ti ti-send"></i></button>
      </div>
    </div>

    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:8px;">
        <h3 style="margin:0;"><i class="ti ti-terminal"></i> লাইভ অ্যাক্টিভিটি টার্মিনাল</h3>
        <div style="display:flex; gap:6px;">
          <button onclick="copyTerminalLogs()" style="padding:6px 12px; font-size:11px; background:#0284c7; color:#fff; border:none; border-radius:8px; cursor:pointer; font-weight:700;">কপি</button>
          <button onclick="fetchLiveUpdates()" style="padding:6px 12px; font-size:11px; background:#059669; color:#fff; border:none; border-radius:8px; cursor:pointer; font-weight:700;">রিফ্রেশ</button>
          <button onclick="clearTerminalLogs(${bot.id})" style="padding:6px 12px; font-size:11px; background:#b91c1c; color:#fff; border:none; border-radius:8px; cursor:pointer; font-weight:700;">ক্লিয়ার</button>
        </div>
      </div>
      <div class="terminal-window" id="terminalBox">
        <div class="log-line"><span class="log-time">[System]</span> টার্মিনাল প্রস্তুত...</div>
      </div>
    </div>
  </div>

  <div id="pane-products" class="dash-pane" style="display:none;">
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; flex-wrap:wrap; gap:8px;">
        <h3 style="margin:0;"><i class="ti ti-box"></i> পণ্য ম্যানেজমেন্ট ও শপ লিংক</h3>
        <div style="display:flex; gap:8px;">
          <a href="${escapeHtml(storePublicUrl)}" target="_blank" style="font-size:12px; background:#dcfce7; color:#15803d; padding:7px 14px; border-radius:999px; font-weight:700; text-decoration:none;">🌐 লাইভ শপ</a>
          <a href="/catalog-builder" target="_blank" style="font-size:12px; background:#e0f2fe; color:#0369a1; padding:7px 14px; border-radius:999px; font-weight:700; text-decoration:none;">🛠️ ক্যাটালগ বিল্ডার</a>
        </div>
      </div>

      <div class="grid-2" style="margin-bottom:16px;">
        <div style="background:rgba(236,253,245,0.9); border:1px solid #a7f3d0; border-radius:14px; padding:12px;">
          <div style="font-size:11px; font-weight:800; color:#065f46; margin-bottom:5px;">🛍️ কাস্টমার শপ লিংক:</div>
          <div style="display:flex; gap:6px;">
            <input type="text" id="storeShareLink" readonly value="${escapeHtml(storePublicUrl)}" style="padding:8px 10px; font-size:12px; font-weight:700; color:#059669;">
            <button onclick="copyValue('storeShareLink')" style="padding:0 12px; background:#059669; color:#fff; border:none; border-radius:8px; font-size:12px; font-weight:700; cursor:pointer;">কপি</button>
          </div>
        </div>
        <div style="background:rgba(224,242,254,0.9); border:1px solid #bae6fd; border-radius:14px; padding:12px;">
          <div style="font-size:11px; font-weight:800; color:#0369a1; margin-bottom:5px;">🎛️ আপনার ড্যাশবোর্ড লিংক:</div>
          <div style="display:flex; gap:6px;">
            <input type="text" id="dashShareLink" readonly value="${escapeHtml(dashPublicUrl)}" style="padding:8px 10px; font-size:12px; font-weight:700; color:#0284c7;">
            <button onclick="copyValue('dashShareLink')" style="padding:0 12px; background:#0284c7; color:#fff; border:none; border-radius:8px; font-size:12px; font-weight:700; cursor:pointer;">কপি</button>
          </div>
        </div>
      </div>

      <div id="dashFormBox" style="background:rgba(255,255,255,0.65); border:1px solid rgba(226,232,240,0.9); border-radius:16px; padding:16px; margin-bottom:18px;">
        <div id="dashFormTitle" style="font-size:14px; font-weight:800; color:#065f46; margin-bottom:12px;">➕ নতুন প্রোডাক্ট যোগ করুন</div>
        <input type="hidden" id="dashEditProductId" value="">
        <div class="grid-2" style="margin-bottom:10px;">
          <input type="text" id="dashPName" placeholder="পণ্যের নাম (যেমন: M10 TWS Earbuds)">
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
            <input type="number" id="dashPPrice" placeholder="বর্তমান মূল্য (৳)">
            <input type="number" id="dashPRegPrice" placeholder="আগের মূল্য (৳)">
          </div>
        </div>
        <div class="grid-2" style="margin-bottom:10px;">
          <div style="display:flex; gap:6px;">
            <select id="dashCatSelect" onchange="onDashCatSelect(this)" style="display:none; max-width:48%;"></select>
            <input type="text" id="dashPCat" placeholder="ক্যাটাগরি (যেমন: গ্যাজেট)">
          </div>
          <input type="text" id="dashPLink" placeholder="কাস্টম বাই লিংক (অপশনাল)">
        </div>
        <div class="grid-2" style="margin-bottom:10px;">
          <div onclick="document.getElementById('dashPImgFile').click()" style="border:2px dashed #059669; border-radius:12px; padding:12px; text-align:center; cursor:pointer; background:rgba(236,253,245,0.7); min-height:86px; display:flex; align-items:center; justify-content:center;">
            <span id="dashImgText" style="font-size:12px; color:#047857; font-weight:700;"><i class="ti ti-camera"></i> মূল ছবি আপলোড</span>
            <img id="dashImgPreview" style="display:none; max-height:70px; border-radius:6px;">
            <input type="file" id="dashPImgFile" accept="image/*" style="display:none;" onchange="handleDashImgSelect(event)">
          </div>
          <div onclick="document.getElementById('dashPDemoImgFile').click()" style="border:2px dashed #6366f1; border-radius:12px; padding:12px; text-align:center; cursor:pointer; background:rgba(238,242,255,0.7); min-height:86px; display:flex; flex-direction:column; align-items:center; justify-content:center;">
            <span id="dashDemoImgText" style="font-size:12px; color:#4f46e5; font-weight:700;"><i class="ti ti-photo-plus"></i> ডেমো গ্যালারি (সর্বোচ্চ ৮টি)</span>
            <div id="dashDemoGalleryBox" style="display:none; flex-wrap:wrap; gap:6px; margin-top:6px;"></div>
            <input type="file" id="dashPDemoImgFile" accept="image/*" multiple style="display:none;" onchange="handleDashMultipleDemoImgSelect(event)">
          </div>
        </div>
        <textarea id="dashPDesc" rows="2" placeholder="পণ্যের বিবরণ বা সাইজ/কালার..." style="margin-bottom:10px;"></textarea>
        <div style="display:flex; gap:8px;">
          <button id="btnDashSave" class="primary-btn" onclick="saveOrUpdateProductDirect(${bot.id})" style="flex:1;"><i class="ti ti-plus"></i> প্রোডাক্ট সেভ করুন</button>
          <button id="btnDashCancelEdit" onclick="cancelDashEdit()" style="display:none; padding:0 18px; background:#64748b; color:#fff; border:none; border-radius:12px; font-weight:700; cursor:pointer;">বাতিল</button>
        </div>
      </div>

      <div id="dashProductTableContainer"><div style="text-align:center; padding:14px; color:var(--muted);">পণ্য লোড হচ্ছে...</div></div>
    </div>
  </div>

  <div id="pane-settings" class="dash-pane" style="display:none;">
    <div class="card">
      <h3><i class="ti ti-edit"></i> বটের তথ্য ও ওয়েবসাইট অ্যানালাইজার</h3>
      <div class="grid-2">
        <div class="form-group">
          <label>বটের / দোকানের নাম:</label>
          <input type="text" id="editBotName" value="${escapeHtml(bot.bot_name)}">
        </div>
        <div class="form-group">
          <label>অর্ডার অ্যালার্ট WhatsApp নম্বর:</label>
          <input type="text" id="editAlertPhone" value="${escapeHtml(bot.alert_phone || '')}" placeholder="017XXXXXXXX">
        </div>
      </div>
      <div class="form-group">
        <label>ওয়েবসাইট লিংক (AI অটো-অ্যানালাইজ):</label>
        <div style="display:flex; gap:8px;">
          <input type="url" id="editSiteUrl" value="${escapeHtml(bot.website_url || '')}" placeholder="https://example.com" style="flex:1;">
          <button onclick="reanalyzeWebsite(${bot.id}, this)" style="padding:0 16px; background:#0284c7; color:#fff; border:none; border-radius:12px; font-weight:700; cursor:pointer; white-space:nowrap;">রি-অ্যানালাইজ</button>
        </div>
      </div>

      <div id="trialLockBanner" style="display:none; background:rgba(238,242,255,0.9); border:1px solid #c7d2fe; border-radius:14px; padding:14px; margin-bottom:14px; text-align:center;">
        <div style="font-weight:800; color:#3730a3; font-size:13px;" id="trialLockMsg"></div>
        <div style="display:flex; justify-content:center; gap:8px; margin-top:10px;" id="trialBtnGrp">
          <button onclick="claim10DaysTrial(${bot.id})" style="padding:8px 14px; background:#4f46e5; color:#fff; border:none; border-radius:10px; font-size:12px; font-weight:700; cursor:pointer;">🎁 ১০ দিন ফ্রি ট্রায়াল</button>
        </div>
      </div>

      <div class="grid-2">
        <div class="form-group">
          <label>বটের ধরন:</label>
          <select id="editBotType">
            <option value="business_site" ${bot.bot_type === 'business_site' ? 'selected' : ''}>🌐 ই-কমার্স ওয়েবসাইট</option>
            <option value="catalog_link" ${bot.bot_type === 'catalog_link' ? 'selected' : ''}>📦 ডিজিটাল ক্যাটালগ</option>
            <option value="business_no_site" ${bot.bot_type === 'business_no_site' ? 'selected' : ''}>🏬 সাধারণ দোকান</option>
            <option value="personal" ${bot.bot_type === 'personal' ? 'selected' : ''}>👤 পার্সোনাল সহকারী</option>
          </select>
        </div>
        <div class="form-group">
          <label>এআই তথ্যের উৎস (Knowledge Source):</label>
          <select id="editKnowledgeSource">
            <option value="catalog" ${bot.knowledge_source === 'catalog' ? 'selected' : ''}>📦 নিজস্ব প্রোডাক্ট ক্যাটালগ</option>
            <option value="website" ${bot.knowledge_source === 'website' ? 'selected' : ''}>🌐 ওয়েবসাইট লিংক</option>
          </select>
        </div>
      </div>

      <div class="form-group">
        <label>এআই নির্দেশিকা / বিবরণ:</label>
        <textarea id="editPrompt" rows="3">${escapeHtml(bot.system_prompt || '')}</textarea>
      </div>
      <div class="grid-2">
        <div class="form-group"><label>ডেলিভারি (ভেতরে ৳):</label><input type="number" id="editDelIn" value="${Number(bot.delivery_inside || 70)}"></div>
        <div class="form-group"><label>ডেলিভারি (বাইরে ৳):</label><input type="number" id="editDelOut" value="${Number(bot.delivery_outside || 130)}"></div>
      </div>
      <button class="primary-btn" onclick="saveBotSettings(${bot.id})"><i class="ti ti-device-floppy"></i> সেটিংস সেভ করুন</button>
    </div>

    <div class="card">
      <h3><i class="ti ti-palette"></i> থিম কালার পরিবর্তন</h3>
      <div class="color-picker">
        <div class="color-dot" style="background:#059669;" onclick="changeTheme('#059669')"></div>
        <div class="color-dot" style="background:#0284c7;" onclick="changeTheme('#0284c7')"></div>
        <div class="color-dot" style="background:#8b5cf6;" onclick="changeTheme('#8b5cf6')"></div>
        <div class="color-dot" style="background:#f43f5e;" onclick="changeTheme('#f43f5e')"></div>
        <div class="color-dot" style="background:#d97706;" onclick="changeTheme('#d97706')"></div>
      </div>
    </div>
  </div>

  <div id="pane-billing" class="dash-pane" style="display:none;">
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
        <h3 style="margin:0;"><i class="ti ti-crown" style="color:#d97706;"></i> প্রিমিয়াম আপগ্রেড</h3>
        <span style="font-size:12px; color:#059669; font-weight:800;">ফি: ৳৩০০ / মাস</span>
      </div>
      <div class="pay-methods">
        <div class="pay-badge active" onclick="selectPay('bKash', '${bkash}', this)">bKash</div>
        <div class="pay-badge" onclick="selectPay('Nagad', '${nagad}', this)">Nagad</div>
        <div class="pay-badge" onclick="selectPay('Rocket', '${rocket}', this)">Rocket</div>
      </div>
      <div style="background:rgba(255,255,255,0.7); border:1px solid rgba(226,232,240,0.9); border-radius:14px; padding:16px;">
        <div style="font-size:13px; font-weight:700; margin-bottom:10px;" id="sendNumberNotice">
          👉 bKash Send Money: <span style="color:#059669;">${bkash}</span>
        </div>
        <div class="grid-2" style="margin-bottom:10px;">
          <input type="text" id="senderNumber" placeholder="যে নম্বর থেকে পাঠিয়েছেন">
          <input type="text" id="trxId" placeholder="Transaction ID (TrxID)">
        </div>
        <button class="primary-btn" onclick="submitPayment(${bot.id})"><i class="ti ti-send"></i> ভেরিফিকেশনের জন্য জমা দিন</button>
      </div>
    </div>

    <div class="card">
      <h3><i class="ti ti-key"></i> Gemini Multi-Key ম্যানেজার</h3>
      <div class="form-group">
        <label>কমা (,) দিয়ে একাধিক Gemini API Key যুক্ত করুন:</label>
        <textarea id="apiKeyInput" rows="3" placeholder="AIzaSy1..., AIzaSy2...">${escapeHtml(bot.gemini_api_key || '')}</textarea>
      </div>
      <button class="primary-btn" onclick="saveApiKey(${bot.id})"><i class="ti ti-device-floppy"></i> API Keys সংরক্ষণ করুন</button>
    </div>
  </div>

  <div style="text-align:center; padding:18px; font-size:13px; font-weight:700; color:var(--muted); display:flex; flex-wrap:wrap; justify-content:center; gap:10px; align-items:center;">
    <span>Platform by <b>Sojib</b></span>
    <a href="https://wa.me/8801404277094" target="_blank" style="display:inline-flex;align-items:center;gap:5px;background:linear-gradient(135deg,#059669,#047857);color:#fff;padding:5px 12px;border-radius:999px;text-decoration:none;font-size:12px;font-weight:800;"><i class="ti ti-crown" style="color:#fde047;"></i> <i class="ti ti-brand-whatsapp"></i> 01404277094</a>
    <a href="https://tiktok.com/@sojib_music" target="_blank" style="display:inline-flex;align-items:center;gap:5px;background:#0f172a;color:#fff;padding:5px 12px;border-radius:999px;text-decoration:none;font-size:12px;font-weight:800;"><i class="ti ti-brand-tiktok"></i> @sojib_music</a>
  </div>
</div>

<script>
  const BOT_ID = ${Number(bot.id)};
  const STORE_BASE_URL = ${JSON.stringify(storePublicUrl)};
  let currentMethod = 'bKash';
  let dashCurrentImgBase64 = '';
  let dashCurrentDemoImgBase64 = '';
  let dashDemoImagesArray = [];
  let loadedProductsList = [];

  function switchDashTab(paneId, btn) {
    document.querySelectorAll('.dash-pane').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    document.getElementById(paneId).style.display = 'block';
    btn.classList.add('active');
  }

  function copyValue(id) {
    const el = document.getElementById(id);
    navigator.clipboard.writeText(el.value).then(() => alert('কপি হয়েছে!'));
  }

  function selectPay(method, number, el) {
    currentMethod = method;
    document.querySelectorAll('.pay-badge').forEach(b => b.classList.remove('active'));
    el.classList.add('active');
    document.getElementById('sendNumberNotice').innerHTML = '👉 ' + method + ' Send Money: <span style="color:#059669;">' + number + '</span>';
  }

  async function saveBotSettings(botId) {
    const payload = {
      botId,
      bot_name: document.getElementById('editBotName').value.trim(),
      alert_phone: document.getElementById('editAlertPhone').value.trim(),
      knowledge_source: document.getElementById('editKnowledgeSource').value,
      bot_type: document.getElementById('editBotType').value,
      system_prompt: document.getElementById('editPrompt').value.trim(),
      delivery_inside: document.getElementById('editDelIn').value,
      delivery_outside: document.getElementById('editDelOut').value
    };
    const res = await fetch('/api/user/update-bot-settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const d = await res.json();
    alert(d.message);
  }

  async function submitPayment(botId) {
    const sender = document.getElementById('senderNumber').value.trim();
    const trxId = document.getElementById('trxId').value.trim();
    if (!sender || !trxId) return alert('সেন্ডার নম্বর এবং TrxID দিন!');
    const res = await fetch('/api/user/submit-payment', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ botId, method: currentMethod, sender, trxId }) });
    const d = await res.json();
    alert(d.message);
  }

  async function fetchLiveUpdates() {
    try {
      const res = await fetch('/api/user/bot-logs?botId=' + BOT_ID);
      const data = await res.json();
      if (data.success) {
        if (data.logs && data.logs.length > 0) {
          document.getElementById('terminalBox').innerHTML = data.logs.map(l =>
            '<div class="log-line"><span class="log-time">[' + l.time + ']</span> ' + String(l.message || '').replace(/</g, '&lt;') + '</div>'
          ).join('');
        }
        if (data.stats) {
          document.getElementById('tokenVal').innerText = data.stats.tokens;
          document.getElementById('reqVal').innerText = data.stats.requests;
        }
      }
    } catch (e) {}
  }
  setInterval(fetchLiveUpdates, 3500);
  fetchLiveUpdates();

  async function saveApiKey(botId) {
    const apiKey = document.getElementById('apiKeyInput').value.trim();
    const res = await fetch('/api/user/update-api-key', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ botId, apiKey }) });
    const d = await res.json();
    alert(d.message);
  }

  async function requestPairingCode(botId) {
    const phone = document.getElementById('phoneInput').value;
    if (!phone) return alert('ফোন নম্বর দিন!');
    document.getElementById('codeBanner').style.display = 'block';
    document.getElementById('codeDisplay').innerText = 'লোড হচ্ছে...';
    const res = await fetch('/api/request-pairing-code', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ botId, phone }) });
    const d = await res.json();
    if (d.success) document.getElementById('codeDisplay').innerText = d.pairingCode;
    else { document.getElementById('codeDisplay').innerText = 'ব্যর্থ'; alert(d.message || 'কোড তৈরি হয়নি'); }
  }

  async function changeTheme(color) {
    document.documentElement.style.setProperty('--primary', color);
    await fetch('/api/user/update-theme', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ botId: BOT_ID, themeColor: color }) });
  }

  async function sendTestChatMessage(botId) {
    const input = document.getElementById('testMsgInput');
    const btn = document.getElementById('testSendBtn');
    const text = input.value.trim();
    if (!text) return;
    const win = document.getElementById('testChatWindow');
    const safeText = text.replace(/</g, '&lt;');
    win.innerHTML += '<div style="margin-bottom:8px;text-align:right;"><span style="background:#059669;color:#fff;padding:7px 12px;border-radius:12px;display:inline-block;">' + safeText + '</span></div>';
    input.value = '';
    const typingId = 'typing_' + Date.now();
    win.innerHTML += '<div id="' + typingId + '" style="margin-bottom:8px;"><span style="background:#e2e8f0;color:#475569;padding:6px 12px;border-radius:12px;display:inline-block;font-size:12px;">টাইপ করছে...</span></div>';
    win.scrollTop = win.scrollHeight;
    btn.disabled = true;
    try {
      const res = await fetch('/api/user/test-chat', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ botId, message: text }) });
      const d = await res.json();
      const tEl = document.getElementById(typingId); if (tEl) tEl.remove();
      const safeReply = String(d.reply || 'কোনো উত্তর নেই').replace(/</g, '&lt;').replace(/\\n/g, '<br>');
      win.innerHTML += '<div style="margin-bottom:8px;"><span style="background:#f8fafc;border:1px solid #cbd5e1;color:#0f172a;padding:8px 12px;border-radius:12px;display:inline-block;line-height:1.45;">' + safeReply + '</span></div>';
      win.scrollTop = win.scrollHeight;
    } catch (e) {
      const tEl = document.getElementById(typingId); if (tEl) tEl.remove();
    } finally { btn.disabled = false; }
  }

  function copyTerminalLogs() {
    navigator.clipboard.writeText(document.getElementById('terminalBox').innerText).then(() => alert('টার্মিনাল লগ কপি হয়েছে!'));
  }

  async function clearTerminalLogs(botId) {
    if (!confirm('লগ মুছে ফেলতে চান?')) return;
    await fetch('/api/user/clear-logs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ botId }) });
    fetchLiveUpdates();
  }

  async function reanalyzeWebsite(botId, btn) {
    const url = document.getElementById('editSiteUrl').value.trim();
    if (!url) return alert('ওয়েবসাইট লিংক দিন!');
    const orig = btn.innerText;
    btn.innerText = 'যাচাই হচ্ছে...';
    try {
      const res = await fetch('/api/user/reanalyze-site', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ botId, website_url: url }) });
      const d = await res.json();
      if (d.requires_upgrade) {
        document.getElementById('trialLockBanner').style.display = 'block';
        document.getElementById('trialLockMsg').innerText = d.message;
        return;
      }
      alert(d.message);
      if (d.success) location.reload();
    } finally { btn.innerText = orig; }
  }

  async function claim10DaysTrial(botId) {
    if (!confirm('১০ দিনের ফ্রি ট্রায়াল চালু করতে চান?')) return;
    const res = await fetch('/api/user/claim-trial', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ botId }) });
    const d = await res.json();
    alert(d.message);
    if (d.success) location.reload();
  }

  function handleDashImgSelect(e) {
    const file = e.target.files[0]; if (!file) return;
    const reader = new FileReader();
    reader.onload = function(evt) {
      const img = new Image();
      img.onload = function() {
        const canvas = document.createElement('canvas');
        const maxDim = 600; let w = img.width, h = img.height;
        if (w > h && w > maxDim) { h = Math.round((h * maxDim) / w); w = maxDim; }
        else if (h > maxDim) { w = Math.round((w * maxDim) / h); h = maxDim; }
        canvas.width = w; canvas.height = h;
        canvas.getContext('2d').drawImage(img, 0, 0, w, h);
        dashCurrentImgBase64 = canvas.toDataURL('image/jpeg', 0.65);
        document.getElementById('dashImgPreview').src = dashCurrentImgBase64;
        document.getElementById('dashImgPreview').style.display = 'block';
        document.getElementById('dashImgText').style.display = 'none';
      };
      img.src = evt.target.result;
    };
    reader.readAsDataURL(file);
  }

  function handleDashMultipleDemoImgSelect(e) {
    const files = Array.from(e.target.files).slice(0, 8);
    if (!files.length) return;
    dashDemoImagesArray = [];
    const gallery = document.getElementById('dashDemoGalleryBox');
    gallery.innerHTML = '';
    let done = 0;
    files.forEach(file => {
      const reader = new FileReader();
      reader.onload = evt => {
        const img = new Image();
        img.onload = () => {
          const canvas = document.createElement('canvas');
          const maxDim = 600; let w = img.width, h = img.height;
          if (w > h && w > maxDim) { h = Math.round((h * maxDim) / w); w = maxDim; }
          else if (h > maxDim) { w = Math.round((w * maxDim) / h); h = maxDim; }
          canvas.width = w; canvas.height = h;
          canvas.getContext('2d').drawImage(img, 0, 0, w, h);
          const b64 = canvas.toDataURL('image/jpeg', 0.65);
          dashDemoImagesArray.push(b64);
          gallery.innerHTML += '<img src="' + b64 + '" style="width:38px;height:38px;border-radius:6px;object-fit:cover;">';
          done++;
          if (done === files.length) {
            gallery.style.display = 'flex';
            document.getElementById('dashDemoImgText').innerText = '✅ ' + dashDemoImagesArray.length + 'টি ছবি যুক্ত হয়েছে';
            dashCurrentDemoImgBase64 = JSON.stringify(dashDemoImagesArray);
          }
        };
        img.src = evt.target.result;
      };
      reader.readAsDataURL(file);
    });
  }

  async function loadDashProducts() {
    try {
      const res = await fetch('/api/user/products?botId=' + BOT_ID);
      const data = await res.json();
      const container = document.getElementById('dashProductTableContainer');
      if (!data.success) return;
      loadedProductsList = data.products || [];
      if (loadedProductsList.length === 0) {
        container.innerHTML = '<div style="text-align:center;padding:20px;color:#64748b;font-size:13px;">কোনো পণ্য এখনো যোগ করা হয়নি।</div>';
        return;
      }
      updateDashCategoryDropdown(loadedProductsList);
      container.innerHTML = loadedProductsList.map((p, idx) => {
        const singleLink = p.buy_link || (STORE_BASE_URL + '/p/' + p.id);
        const safeName = String(p.name || '').replace(/</g, '&lt;');
        const safeCat = String(p.category || 'General').replace(/</g, '&lt;');
        return '<div style="background:rgba(255,255,255,0.75);border:1px solid rgba(226,232,240,0.9);border-radius:14px;padding:12px;margin-bottom:10px;">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;">' +
            '<div style="display:flex;align-items:center;gap:10px;">' +
              (p.image_url ? '<img src="' + p.image_url + '" style="width:52px;height:52px;border-radius:10px;object-fit:cover;">' : '<div style="width:52px;height:52px;border-radius:10px;background:#f1f5f9;display:flex;align-items:center;justify-content:center;color:#94a3b8;"><i class="ti ti-photo"></i></div>') +
              '<div><b style="font-size:14px;">' + safeName + '</b><br><span style="color:#059669;font-weight:800;">৳' + p.price + '</span> <span style="font-size:11px;background:#ecfdf5;color:#047857;padding:2px 8px;border-radius:999px;font-weight:700;">' + safeCat + '</span></div>' +
            '</div>' +
            '<div style="display:flex;gap:6px;">' +
              '<button onclick="startEditDashProduct(' + idx + ')" style="padding:6px 12px;background:#e0f2fe;color:#0369a1;border:none;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer;">এডিট</button>' +
              '<button onclick="deleteDashProduct(' + p.id + ')" style="padding:6px 12px;background:#fee2e2;color:#b91c1c;border:none;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer;">ডিলিট</button>' +
            '</div>' +
          '</div>' +
          '<div style="display:flex;gap:6px;margin-top:8px;align-items:center;">' +
            '<input type="text" readonly value="' + singleLink + '" style="padding:6px 10px;font-size:11px;color:#059669;font-weight:700;">' +
            '<button onclick="navigator.clipboard.writeText(\\'' + singleLink + '\\');alert(\\'লিংক কপি হয়েছে!\\')" style="padding:6px 12px;background:#059669;color:#fff;border:none;border-radius:8px;font-size:11px;font-weight:700;cursor:pointer;white-space:nowrap;">কপি</button>' +
          '</div>' +
        '</div>';
      }).join('');
    } catch (e) {}
  }

  async function saveOrUpdateProductDirect(botId) {
    const editId = document.getElementById('dashEditProductId').value;
    const name = document.getElementById('dashPName').value.trim();
    const price = document.getElementById('dashPPrice').value.trim();
    if (!name || !price) return alert('পণ্যের নাম ও মূল্য দিন!');
    const url = editId ? '/api/user/products/update' : '/api/user/products/add';
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        botId,
        productId: editId || undefined,
        name,
        price,
        regular_price: document.getElementById('dashPRegPrice').value.trim() || null,
        category: document.getElementById('dashPCat').value.trim() || 'General',
        buy_link: document.getElementById('dashPLink').value.trim(),
        description: document.getElementById('dashPDesc').value.trim(),
        image_url: dashCurrentImgBase64,
        demo_images: dashCurrentDemoImgBase64
      })
    });
    const d = await res.json();
    alert(d.message || 'সম্পন্ন!');
    if (d.success) { cancelDashEdit(); loadDashProducts(); }
  }

  function startEditDashProduct(idx) {
    const p = loadedProductsList[idx]; if (!p) return;
    document.getElementById('dashEditProductId').value = p.id;
    document.getElementById('dashPName').value = p.name;
    document.getElementById('dashPPrice').value = p.price;
    document.getElementById('dashPRegPrice').value = p.regular_price || '';
    document.getElementById('dashPCat').value = p.category || 'General';
    document.getElementById('dashPLink').value = p.buy_link || '';
    document.getElementById('dashPDesc').value = p.description || '';
    dashCurrentImgBase64 = p.image_url || '';
    if (dashCurrentImgBase64) {
      document.getElementById('dashImgPreview').src = dashCurrentImgBase64;
      document.getElementById('dashImgPreview').style.display = 'block';
      document.getElementById('dashImgText').style.display = 'none';
    }
    dashCurrentDemoImgBase64 = p.demo_images || '';
    const gallery = document.getElementById('dashDemoGalleryBox');
    gallery.innerHTML = '';
    if (dashCurrentDemoImgBase64) {
      let arr = [];
      try { arr = JSON.parse(dashCurrentDemoImgBase64); if (!Array.isArray(arr)) arr = [dashCurrentDemoImgBase64]; }
      catch (e) { arr = [dashCurrentDemoImgBase64]; }
      arr.forEach(src => { gallery.innerHTML += '<img src="' + src + '" style="width:38px;height:38px;border-radius:6px;object-fit:cover;">'; });
      gallery.style.display = 'flex';
      document.getElementById('dashDemoImgText').innerText = '✅ ' + arr.length + 'টি ডেমো ছবি লোড হয়েছে';
    }
    document.getElementById('dashFormTitle').innerText = '✏️ পণ্য এডিট করুন: ' + p.name;
    document.getElementById('btnDashSave').innerHTML = '<i class="ti ti-check"></i> পণ্য আপডেট করুন';
    document.getElementById('btnDashCancelEdit').style.display = 'inline-block';
    document.getElementById('dashFormBox').scrollIntoView({ behavior: 'smooth' });
  }

  function cancelDashEdit() {
    ['dashEditProductId','dashPName','dashPPrice','dashPRegPrice','dashPCat','dashPLink','dashPDesc','dashPImgFile','dashPDemoImgFile'].forEach(id => {
      document.getElementById(id).value = '';
    });
    dashCurrentImgBase64 = ''; dashCurrentDemoImgBase64 = ''; dashDemoImagesArray = [];
    document.getElementById('dashImgPreview').style.display = 'none';
    document.getElementById('dashImgText').style.display = 'block';
    document.getElementById('dashDemoGalleryBox').innerHTML = '';
    document.getElementById('dashDemoGalleryBox').style.display = 'none';
    document.getElementById('dashDemoImgText').innerHTML = '<i class="ti ti-photo-plus"></i> ডেমো গ্যালারি (সর্বোচ্চ ৮টি)';
    document.getElementById('dashFormTitle').innerText = '➕ নতুন প্রোডাক্ট যোগ করুন';
    document.getElementById('btnDashSave').innerHTML = '<i class="ti ti-plus"></i> প্রোডাক্ট সেভ করুন';
    document.getElementById('btnDashCancelEdit').style.display = 'none';
  }

  function updateDashCategoryDropdown(products) {
    const cats = Array.from(new Set(products.map(p => (p.category || '').trim()).filter(c => c && c !== 'General')));
    const sel = document.getElementById('dashCatSelect');
    if (cats.length > 0) {
      sel.style.display = 'block';
      sel.innerHTML = '<option value="">-- ক্যাটাগরি --</option>' + cats.map(c => '<option value="' + c + '">' + c + '</option>').join('');
    } else sel.style.display = 'none';
  }

  function onDashCatSelect(el) { if (el.value) document.getElementById('dashPCat').value = el.value; }

  async function deleteDashProduct(productId) {
    if (!confirm('এই পণ্যটি মুছে ফেলতে চান?')) return;
    const res = await fetch('/api/user/products/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ botId: BOT_ID, productId }) });
    const d = await res.json();
    if (d.success) loadDashProducts();
  }

  loadDashProducts();
</script>
</body>
</html>`;
}

// ================= AI মেসেজ এক্সিকিউশন (Gemini Models 100% Untouched) =================
async function executeGeminiForTenant(botRow, userPrompt, systemPrompt, imageBuffer = null, imageMime = 'image/jpeg') {
  const dailyLimit = botRow.rate_limit_daily || 300;
  if ((botRow.requests_today || 0) >= dailyLimit && botRow.plan !== 'premium') {
    addBotLog(botRow.id, 'warn', `⚠️ আজকের ফ্রি লিমিট (${dailyLimit} মেসেজ) শেষ!`);
    return 'ভাইয়া, আজকের জন্য আমাদের স্বয়ংক্রিয় এআই সেবার ফ্রি লিমিট শেষ হয়ে গিয়েছে। আরও আনলিমিটেড সেবার জন্য অ্যাডমিনের সাথে যোগাযোগ করুন ❤️';
  }

  let reply = '';
  let usedTokens = 0;
  const safeInstruction = typeof systemPrompt === 'string' && systemPrompt.trim() ? systemPrompt.trim() : 'তুমি একজন অমায়িক ও পেশাদার কাস্টমার সহকারী।';

  const customKeys = (botRow.gemini_api_key || '')
    .split(',')
    .map(k => k.trim())
    .filter(k => k.length > 20);

  if (customKeys.length > 0) {
    const modelsToTry = [GEMINI_MODEL, ...(GEMINI_FALLBACK_MODELS || [])].filter(Boolean);
    for (let i = 0; i < customKeys.length; i++) {
      const activeKey = customKeys[i];
      const client = new GoogleGenAI({ apiKey: activeKey });
      const contents = [];
      if (imageBuffer) contents.push({ inlineData: { data: imageBuffer.toString('base64'), mimeType: imageMime } });
      contents.push(userPrompt);

      for (const modelId of modelsToTry) {
        try {
          const response = await client.models.generateContent({
            model: modelId,
            contents,
            config: {
              systemInstruction: safeInstruction,
              temperature: 0.35,
              maxOutputTokens: 1200
            }
          });

          reply = response.text?.trim() || response.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '';
          usedTokens = response.usageMetadata?.totalTokenCount || 50;
          if (reply) break;
        } catch (err) {
          if ((err.message || '').includes('429')) break;
        }
      }
      if (reply) break;
      addBotLog(botRow.id, 'warn', `⚠️ Personal Key #${i + 1} কাজ করেনি, পরবর্তী Key দেখা হচ্ছে...`);
    }
  }

  if (!reply) {
    try {
      reply = await callGeminiUltraFast(userPrompt, safeInstruction, imageBuffer, imageMime);
      usedTokens = 45;
    } catch (fallbackErr) {
      addBotLog(botRow.id, 'warn', `প্ল্যাটফর্ম ব্যাকআপ এরর: ${fallbackErr.message}`);
    }
  }

  if (!reply) {
    return '⚠️ কোনো Gemini API Key সেট করা নেই! অনুগ্রহ করে "প্রিমিয়াম ও API Key" ট্যাবে আপনার Gemini API Key বসিয়ে সেভ করুন।';
  }

  try {
    await pool.query(
      `UPDATE whatsapp_bots 
       SET tokens_used = COALESCE(tokens_used, 0) + $1, 
           requests_today = COALESCE(requests_today, 0) + 1 
       WHERE id = $2`,
      [usedTokens, botRow.id]
    );
  } catch (e) {}

  return reply;
}

// ================= ডাইনামিক AI মেসেজ হ্যান্ডলার =================
async function handleDynamicCustomerMessage(botRow, customerPhone, text, sock, imageBuffer = null, imageMime = null) {
  const cleanInput = (text || '').trim();
  const botId = botRow.id;

  const historyKey = `${botId}_${customerPhone}`;
  if (!botChatHistories.has(historyKey)) botChatHistories.set(historyKey, []);
  const history = botChatHistories.get(historyKey);

  let combinedQuery = cleanInput;
  if (history.length > 0) {
    const lastUserMsg = [...history].reverse().find(h => h.role === 'user');
    if (lastUserMsg) combinedQuery = `${lastUserMsg.text} ${cleanInput}`;
  }

  let catalogContext = '';
  const source = botRow.knowledge_source || (botRow.bot_type === 'business_site' ? 'website' : 'catalog');

  if (source === 'website' && botRow.website_url) {
    catalogContext = `আমাদের মূল ওয়েবসাইটের তথ্য ও লিংক: ${botRow.website_url}। ওয়েবসাইটের পণ্য ও নিয়মাবলী অনুযায়ী উত্তর দাও: ${botRow.system_prompt || ''}`;
  } else {
    const productsQuery = await pool.query('SELECT * FROM bot_products WHERE bot_id = $1', [botId]);
    const cachedCatalog = productsQuery.rows.map(p => ({
      id: p.id,
      name: p.name,
      price: parseFloat(p.price || 0),
      category: p.category || '',
      in_stock: Boolean(p.in_stock),
      buy_link: p.buy_link || `${botRow.website_url || ''}`,
      description: p.description || ''
    }));

    const searchResult = searchSmartProducts(combinedQuery, cachedCatalog);
    if (searchResult.items && searchResult.items.length > 0) {
      catalogContext = searchResult.items.map(p => `• [ID:${p.id}] ${p.name} | মূল্য: ৳${p.price} | ক্যাটাগরি: ${p.category} | লিংক: ${p.buy_link}`).join('\n');
    }
  }

  const conversationHistoryText = history.length > 0
    ? history.map(h => `${h.role === 'user' ? 'গ্রাহক' : 'অ্যাসিস্ট্যান্ট'}: ${h.text}`).join('\n')
    : 'এখনই কথোপকথন শুরু হয়েছে।';

  let systemPrompt = '';
  if (botRow.bot_type === 'personal') {
    systemPrompt = `তুমি ${botRow.bot_name} এর অত্যন্ত অমায়িক ও সাহায্যকারী ব্যক্তিগত সহকারী (Personal AI Assistant)।
ব্যবহারকারীর নিজস্ব পরিচয়/নির্দেশনা: ${botRow.system_prompt || 'ব্যক্তিগত ইউজার'}।
নিয়মাবলী:
- গ্রাহককে 'ভাইয়া' বা সম্মান দিয়ে কথা বলবে।
- গ্রাহক যা জানতে চাইবে কেবল সেটুকুর প্রাসঙ্গিক ও সংক্ষিপ্ত উত্তর দেবে। অপ্রয়োজনীয় কথা বলবে না।
কথোপকথন ইতিহাস:
${conversationHistoryText}`;
  } else {
    systemPrompt = `তুমি ${botRow.bot_name} এর একজন আসল মানুষের মতো বিনয়ী ও অমায়িক হেল্পডেস্ক/সেলস অ্যাসিস্ট্যান্ট।
ওয়েবসাইট/প্ল্যাটফর্মের মূল বিবরণ ও নির্দেশিকা:
${botRow.system_prompt || 'আমরা মানসম্মত পণ্য ও সেবা দিয়ে থাকি।'}

⛔ অতি গুরুত্বপূর্ণ কঠোর নিয়মাবলী (কখনোই ভঙ্গ করবে না):
১. সাধারণ হাই/হ্যালো/সালাম: গ্রাহক শুধু সালাম বা হাই দিলে বিনয়ের সাথে উত্তর দাও (যেমন: "ওয়ালাইকুম আসসালাম ভাইয়া! কেমন আছেন? আপনাকে কীভাবে সাহায্য করতে পারি?")। কোনো পণ্য, দাম, তালিকা বা ডেলিভারি চার্জ নিজে থেকে জোর করে চাপাবে না!
২. টুর্নামেন্ট/গেমিং/সার্ভিস সাইট হলে: যদি সাইটটি গেমিং, টুর্নামেন্ট বা কোনো সার্ভিসের হয়, তবে সাধারণ মানুষের মতো নিয়ম, রেজিস্ট্রেশন ফি ও প্রসেস সুন্দরভাবে বুঝিয়ে বলো।
৩. পণ্য জানতে চাওয়া: গ্রাহক যতক্ষণ নির্দিষ্ট কোনো পণ্য বা দাম জানতে না চাইবে অথবা কিনতে না চাইবে, ততক্ষণ নিজে থেকে "আপনি কি অর্ডার করতে চান?" বা ডেলিভারি চার্জ বলবে না।
৪. ছবি চাওয়া ও ডেমো পণ্যের নিয়ম:
   - গ্রাহক যখন কোনো পণ্যের ছবি চাইবে বা ডেমো পণ্য দেখতে চাইবে, তখন আমাদের স্টক থেকে ৬-৭টি সেরা পণ্যের নাম, বর্তমান মূল্য, সংক্ষেপ বিবরণ এবং তার "আলাদা আলাদা ডেডিকেটেড লিংক" পয়েন্ট আকারে সুন্দর করে দেবে।
৫. কৃত্রিম বা রোবোটিক আচরণ সম্পূর্ণ নিষিদ্ধ। আসল মানুষের মতো সহজ, সরল ও আন্তরিক ভঙ্গিতে কথা বলো।

স্টক ডাটা রেফারেন্স (প্রয়োজনে ব্যবহারের জন্য):
${catalogContext || 'কোনো নির্দিষ্ট প্রোডাক্ট খোঁজা হয়নি।'}
ডেলিভারি চার্জ (কেবলমাত্র পণ্য অর্ডার করার সময় উল্লেখ করবে): সিটির ভেতরে ৳${botRow.delivery_inside || 70}, বাইরে ৳${botRow.delivery_outside || 130}।
কথোপকথন ইতিহাস:
${conversationHistoryText}`;
  }

  let userPrompt = '';
  if (imageBuffer) {
    userPrompt = `[ছবি বিশ্লেষণ নির্দেশ]: গ্রাহক এই পণ্যের একটি ছবি পাঠিয়েছেন। ছবিটি মনোযোগ দিয়ে দেখো এবং আমাদের স্টকের পণ্যের সাথে মিলিয়ে বলো এই পণ্যটি আমাদের স্টকে আছে কি না। থাকলে তার নাম ও মূল্য জানাও। গ্রাহক ক্যাপশনে লিখেছেন: "${cleanInput || 'এই পণ্যটি কি আপনাদের কাছে আছে?'}"`;
  } else if (cleanInput) {
    userPrompt = `গ্রাহক: "${cleanInput}"`;
  } else {
    userPrompt = 'গ্রাহক একটি বার্তা পাঠিয়েছেন।';
  }

  let reply = await executeGeminiForTenant(botRow, userPrompt, systemPrompt, imageBuffer, imageMime);
  reply = (reply || '').replace(/\*\*/g, '*');

  const lowerText = cleanInput.toLowerCase();
  const isOrderIntent = lowerText.includes('order') || lowerText.includes('অর্ডার') || lowerText.includes('নিতে চাই') || lowerText.includes('কনফার্ম') || lowerText.includes('ঠিকানা');
  const hasPhone = /01[3-9]\d{8}/.test(cleanInput);

  if ((isOrderIntent || hasPhone) && sock) {
    try {
      const ownerAlertNumber = botRow.alert_phone || botRow.phone_number;
      if (ownerAlertNumber) {
        let cleanOwnerPhone = String(ownerAlertNumber).replace(/[^0-9]/g, '');
        if (cleanOwnerPhone.startsWith('01') && cleanOwnerPhone.length === 11) cleanOwnerPhone = '88' + cleanOwnerPhone;
        const ownerJid = cleanOwnerPhone.includes('@s.whatsapp.net') ? cleanOwnerPhone : `${cleanOwnerPhone}@s.whatsapp.net`;

        const alertMsg = `🚨 *নতুন অর্ডার অ্যালার্ট!* 🛍️\n` +
          `━━━━━━━━━━━━━━━━━━━\n` +
          `👤 *দোকান:* ${botRow.bot_name}\n` +
          `📞 *কাস্টমার নম্বর:* +${customerPhone}\n` +
          `💬 *মেসেজ/ঠিকানা:* ${cleanInput}\n` +
          `⏰ *সময়:* ${new Date().toLocaleTimeString('bn-BD')}\n` +
          `━━━━━━━━━━━━━━━━━━━\n` +
          `👉 *কাস্টমারকে কল করতে বা চ্যাট করতে:* wa.me/${customerPhone}`;

        await sock.sendMessage(ownerJid, { text: alertMsg });
        addBotLog(botId, 'success', `🔔 নতুন অর্ডারের নোটিফিকেশন পাঠানো হয়েছে (${cleanOwnerPhone})-এ!`);

        await pool.query(
          `INSERT INTO bot_orders (bot_id, customer_phone, product_details) VALUES ($1, $2, $3)`,
          [botId, customerPhone, cleanInput]
        );
      }
    } catch (orderErr) {
      console.error('[ORDER ALERT ERROR]:', orderErr.message);
    }
  }

  history.push({ role: 'user', text: cleanInput || 'ছবি পাঠিয়েছেন', time: Date.now() });
  history.push({ role: 'assistant', text: reply, time: Date.now() });
  if (history.length > 8) history.shift();

  return reply;
}

// ================= ANTI-BAN Baileys Bot স্টার্টার =================
async function startTenantBot(botId) {
  try {
    const res = await pool.query('SELECT * FROM whatsapp_bots WHERE id = $1', [botId]);
    if (res.rows.length === 0) return null;
    const botRow = res.rows[0];

    const { state, saveCreds } = await usePostgresAuthState(botId);
    const { version } = await fetchLatestBaileysVersion();

    const sock = makeWASocket({
      version,
      logger: pino({ level: 'silent' }),
      auth: state,
      printQRInTerminal: false,
      browser: ['Ubuntu', 'Chrome', '20.0.04'],
      syncFullHistory: false,
      markOnlineOnConnect: true,
      generateHighQualityLinkPreview: true,
      connectTimeoutMs: 60000,
      keepAliveIntervalMs: 25000,
      defaultQueryTimeoutMs: 60000
    });

    activeSockets.set(botId, { sock, state: { connected: false, pairingCode: null } });
    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', async (update) => {
      const { connection, lastDisconnect } = update;
      const b = activeSockets.get(botId);

      if (connection === 'close') {
        if (b) b.state.connected = false;
        await pool.query("UPDATE whatsapp_bots SET status = 'DISCONNECTED' WHERE id = $1", [botId]);
        addBotLog(botId, 'warn', '⚠️ সেশন ডিসকানেক্ট। রি-কানেক্টের চেষ্টা চলছে...');
        if (lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut) {
          setTimeout(() => startTenantBot(botId), 10000);
        }
      } else if (connection === 'open') {
        if (b) {
          b.state.connected = true;
          b.state.pairingCode = null;
        }
        await pool.query("UPDATE whatsapp_bots SET status = 'CONNECTED' WHERE id = $1", [botId]);
        addBotLog(botId, 'success', `🎉 WhatsApp সফলভাবে কানেক্ট হয়েছে!`);
      }
    });

    sock.ev.on('messages.upsert', async ({ messages, type }) => {
      try {
        if (type !== 'notify') return;
        const msg = messages[0];
        if (!msg.message || msg.key.fromMe) return;

        const sender = msg.key.remoteJid;
        if (sender.includes('@g.us')) return;

        const cleanSender = sender.replace(/[^0-9]/g, '');
        const msgContent = msg.message.ephemeralMessage?.message || msg.message.viewOnceMessage?.message || msg.message;
        let text = (msgContent.conversation || msgContent.extendedTextMessage?.text || msgContent.imageMessage?.caption || '').trim();

        const isAudio = Boolean(msgContent.audioMessage);
        const isImage = Boolean(msgContent.imageMessage);
        if (!text && !isAudio && !isImage) return;

        try {
          await sock.readMessages([msg.key]);
          await sock.sendPresenceUpdate('composing', sender);
        } catch (e) {}

        let imageBuffer = null;
        let imageMime = 'image/jpeg';
        if (isImage) {
          try {
            imageBuffer = await downloadMediaMessage(msg, 'buffer', {}, { logger: pino({ level: 'silent' }) });
            imageMime = msgContent.imageMessage.mimetype || 'image/jpeg';
            addBotLog(botId, 'info', `🖼️ [${cleanSender}]: ছবি পাঠিয়েছেন।`);
          } catch (e) {}
        }

        if (isAudio) {
          try {
            const buffer = await downloadMediaMessage(msg, 'buffer', {}, { logger: pino({ level: 'silent' }) });
            text = await transcribeAudioWithGemini(buffer, msgContent.audioMessage.mimetype || 'audio/ogg');
            addBotLog(botId, 'info', `🎤 [${cleanSender} ভয়েস]: "${text}"`);
          } catch (e) {}
        }

        if (!text && !isImage) return;
        if (text) addBotLog(botId, 'info', `📩 [${cleanSender}]: "${text}"`);

        const latestBotRes = await pool.query('SELECT * FROM whatsapp_bots WHERE id = $1', [botId]);
        const currentBotRow = latestBotRes.rows[0] || botRow;

        let reply = await handleDynamicCustomerMessage(currentBotRow, cleanSender, text, sock, imageBuffer, imageMime);
        if (isAudio) reply = `🎤 *ভয়েস রেকর্ড:* "${text}"\n\n${reply}`;

        try { await sock.sendPresenceUpdate('composing', sender); } catch (_) {}
        const typingDelay = Math.min(2500, Math.max(1000, reply.length * 15));
        await delay(typingDelay);

        const wantsPic = /ছবি|পিক|pic|image|photo|দেখাও|দেখান|দেখি|দেখতে চাই/i.test(text) || (isImage && !text) || (isAudio && /আছে|দাম|পণ্য/i.test(text));
        let sentWithImage = false;

        if (wantsPic) {
          try {
            const allProds = await pool.query(
              `SELECT name, image_url, price FROM bot_products 
               WHERE bot_id = $1 AND image_url IS NOT NULL AND image_url != '' 
               ORDER BY id DESC`,
              [botId]
            );

            if (allProds.rows.length > 0) {
              let targetProd = allProds.rows.find(p => text.toLowerCase().includes(p.name.toLowerCase()));
              if (!targetProd) targetProd = allProds.rows[0];

              if (targetProd && targetProd.image_url) {
                let imgBuffer = null;
                if (targetProd.image_url.startsWith('data:image')) {
                  const base64Data = targetProd.image_url.split(',')[1];
                  imgBuffer = Buffer.from(base64Data, 'base64');
                } else if (targetProd.image_url.startsWith('http')) {
                  imgBuffer = { url: targetProd.image_url };
                }

                if (imgBuffer) {
                  await sock.sendMessage(sender, {
                    image: imgBuffer,
                    caption: `📸 *${targetProd.name}* — ৳${targetProd.price}\n\n${reply}`
                  });
                  sentWithImage = true;
                  addBotLog(botId, 'success', `🖼️ কাস্টমারকে [${targetProd.name}] এর ছবি পাঠানো হয়েছে!`);
                }
              }
            }
          } catch (imgErr) {
            console.error('[IMAGE SEND ERROR]:', imgErr.message);
          }
        }

        if (!sentWithImage) {
          await sock.sendMessage(sender, { text: reply });
        }

        await sock.sendPresenceUpdate('paused', sender);
        addBotLog(botId, 'success', `⚡ [এআই উত্তর পাঠানো সম্পন্ন${sentWithImage ? ' (ছবিসহ)' : ''}]`);
      } catch (err) {
        addBotLog(botId, 'warn', `ত্রুটি: ${err.message}`);
      }
    });

    return sock;
  } catch (err) {
    return null;
  }
}

// ================= PUBLIC API ENDPOINTS =================

// 🌐 পাবলিক অ্যাক্টিভ ডোমেইন লিস্ট (বর্তমান হোস্ট ডিফল্ট + অ্যাডমিন থেকে যুক্ত ডোমেইন)
app.get('/api/domains/active', async (req, res) => {
  const currentHost = (req.headers['x-forwarded-host'] || req.headers.host || 'busness-bot.onrender.com')
    .toLowerCase().split(':')[0].trim().replace(/^www\./, '');
  try {
    const dbDomains = await getActivePlatformDomains();
    const domains = Array.from(new Set([currentHost, ...dbDomains].filter(Boolean)));
    res.json({ success: true, defaultDomain: currentHost, domains });
  } catch (e) {
    res.json({ success: true, defaultDomain: currentHost, domains: [currentHost] });
  }
});

// 🛍️ পাবলিক অ্যাক্টিভ স্টোরস শোকেস
app.get('/api/public/stores', async (req, res) => {
  const currentHost = (req.headers['x-forwarded-host'] || req.headers.host || 'busness-bot.onrender.com')
    .toLowerCase().split(':')[0].trim().replace(/^www\./, '');
  try {
    const stores = await pool.query(`
      SELECT b.bot_name, b.subdomain, COALESCE(NULLIF(b.base_domain, ''), NULLIF(h.base_domain, ''), $1) AS base_domain,
             b.bot_type, COALESCE(h.theme_color, '#059669') AS theme_color,
             (SELECT COUNT(*) FROM bot_products p WHERE p.bot_id = b.id) AS product_count
      FROM whatsapp_bots b
      LEFT JOIN hosted_websites h ON b.id = h.bot_id
      WHERE b.subdomain IS NOT NULL AND b.subdomain != ''
      ORDER BY b.id DESC LIMIT 12
    `, [currentHost]);
    res.json({ success: true, stores: stores.rows });
  } catch (e) {
    res.json({ success: true, stores: [] });
  }
});

// 🔍 AI ওয়েবসাইট লিংক অ্যানালাইজার (শুধু লগইনকৃত ইউজারদের জন্য)
app.post('/api/public/analyze-site', requireUserAuth, async (req, res) => {
  try {
    const { website_url } = req.body;
    if (!website_url) return res.status(400).json({ success: false, message: 'ওয়েবসাইট লিংক দিন।' });
    const knowledge = await analyzeAndExtractWebsiteKnowledge(website_url);
    res.json({ success: true, knowledge });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// 📦 ক্যাটালগ সেভ করার API (লগইন ও মালিকানা সুরক্ষিত)
app.post('/api/catalog/save', requireUserAuth, async (req, res) => {
  try {
    const { store_name, catalog_slug, admin_pin, items } = req.body;
    const cleanSlug = String(catalog_slug || '').toLowerCase().trim().replace(/[^a-z0-9-]/g, '');

    if (!cleanSlug) return res.status(400).json({ success: false, message: 'সঠিক স্লাগ কোড দিন।' });

    const existCat = await pool.query('SELECT user_id FROM store_catalogs WHERE catalog_slug = $1', [cleanSlug]);
    if (existCat.rows.length > 0 && existCat.rows[0].user_id && existCat.rows[0].user_id !== req.authUser.id) {
      return res.status(403).json({ success: false, message: '⛔ এই ক্যাটালগ স্লাগটি অন্য একজন ইউজারের দখলে আছে! অন্য নাম দিন।' });
    }

    await pool.query(
      `INSERT INTO store_catalogs (user_id, catalog_slug, store_name, admin_pin)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (catalog_slug) DO UPDATE SET user_id = COALESCE(store_catalogs.user_id, $1), store_name = $3, admin_pin = COALESCE($4, store_catalogs.admin_pin)`,
      [req.authUser.id, cleanSlug, store_name, admin_pin || '1234']
    );

    await pool.query('DELETE FROM store_catalog_items WHERE catalog_slug = $1', [cleanSlug]);

    for (const item of (items || [])) {
      await pool.query(
        `INSERT INTO store_catalog_items (catalog_slug, name, price, category, image_url, demo_images, description)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [cleanSlug, item.name, parseFloat(item.price) || 0, item.category || 'General', item.image_url || '', item.demo_images || '', item.description || '']
      );
    }

    await pool.query(`
      UPDATE bot_products bp
      SET image_url = sci.image_url
      FROM store_catalog_items sci
      WHERE bp.name = sci.name AND sci.catalog_slug = $1
    `, [cleanSlug]);

    const rawHost = (req.headers['x-forwarded-host'] || req.get('host') || 'busness-bot.onrender.com').split(':')[0];
    const catalogUrl = `https://${rawHost}/catalog/${cleanSlug}`;
    res.json({ success: true, catalog_url: catalogUrl, slug: cleanSlug });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get('/api/catalog/get/:slug', requireUserAuth, async (req, res) => {
  try {
    const slug = req.params.slug.toLowerCase().trim();
    const cat = await pool.query('SELECT * FROM store_catalogs WHERE catalog_slug = $1', [slug]);
    if (cat.rows.length === 0) return res.json({ success: false, message: 'নতুন ক্যাটালগ' });

    const items = await pool.query('SELECT * FROM store_catalog_items WHERE catalog_slug = $1 ORDER BY id ASC', [slug]);
    res.json({
      success: true,
      store_name: cat.rows[0].store_name,
      admin_pin: cat.rows[0].admin_pin,
      items: items.rows
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.get('/catalog-builder', (req, res) => {
  if (!getLoggedInUser(req)) return res.status(401).send(generateLoginRequiredPage('ক্যাটালগ বিল্ডার লক'));
  res.sendFile(path.join(__dirname, 'public', 'catalog_builder.html'));
});

// 🔗 প্রতিটি ক্যাটালগ পণ্যের আলাদা ডেডিকেটেড লিংক (/c/:slug/:id)
app.get('/c/:slug/:id', async (req, res) => {
  try {
    const { slug, id } = req.params;
    const cleanSlug = slug.toLowerCase().trim();
    const cat = await pool.query('SELECT * FROM store_catalogs WHERE catalog_slug = $1', [cleanSlug]);
    if (cat.rows.length === 0) return res.status(404).send('<h2>ক্যাটালগ পাওয়া যায়নি!</h2>');

    const itemRes = await pool.query('SELECT * FROM store_catalog_items WHERE id = $1 AND catalog_slug = $2', [parseInt(id, 10), cleanSlug]);
    if (itemRes.rows.length === 0) return res.status(404).send('<h2>পণ্যটি পাওয়া যায়নি!</h2>');

    const item = itemRes.rows[0];
    const store = cat.rows[0];
    const host = (req.headers['x-forwarded-host'] || req.get('host') || 'busness-bot.onrender.com').split(':')[0];
    const pseudoBot = { bot_name: store.store_name, phone_number: '', theme_color: '#059669' };
    return res.send(generateSingleProductPage(pseudoBot, item, host, `catalog/${cleanSlug}`));
  } catch (e) {
    res.status(500).send('Error');
  }
});

// 📖 সম্পূর্ণ ক্যাটালগ ভিউয়ার (/catalog/:slug)
app.get('/catalog/:slug', async (req, res) => {
  try {
    const rawSlug = req.params.slug ? req.params.slug.toLowerCase().trim() : '';
    if (!rawSlug) return res.status(404).send('<h2>ক্যাটালগ পাওয়া যায়নি!</h2>');

    const host = (req.headers['x-forwarded-host'] || req.get('host') || 'busness-bot.onrender.com').split(':')[0];
    const altSlug = rawSlug.includes('diamond')
      ? rawSlug.replace('diamond', 'daimond')
      : (rawSlug.includes('daimond') ? rawSlug.replace('daimond', 'diamond') : rawSlug);

    const cat = await pool.query(
      'SELECT * FROM store_catalogs WHERE LOWER(catalog_slug) = $1 OR LOWER(catalog_slug) = $2 LIMIT 1',
      [rawSlug, altSlug]
    );

    if (cat.rows.length > 0) {
      const store = cat.rows[0];
      const items = await pool.query('SELECT * FROM store_catalog_items WHERE catalog_slug = $1 ORDER BY id DESC', [store.catalog_slug]);
      return res.send(generateStorefrontView({ bot_name: store.store_name }, items.rows, `${host}/catalog/${store.catalog_slug}`, store.catalog_slug, host));
    }

    const botRes = await pool.query(
      `SELECT b.*, h.theme_color FROM whatsapp_bots b LEFT JOIN hosted_websites h ON b.id = h.bot_id 
       WHERE LOWER(b.subdomain) = $1 OR LOWER(b.subdomain) = $2 LIMIT 1`,
      [rawSlug, altSlug]
    );

    if (botRes.rows.length > 0) {
      const bot = botRes.rows[0];
      const prods = await pool.query('SELECT * FROM bot_products WHERE bot_id = $1 ORDER BY id DESC', [bot.id]);
      return res.send(generateStorefrontView(bot, prods.rows, `${host}/${bot.subdomain}`, bot.subdomain, host));
    }

    return res.status(404).send('<h2>ক্যাটালগ পাওয়া যায়নি!</h2>');
  } catch (e) {
    res.status(500).send('Error: ' + e.message);
  }
});

// ================= USER ACCOUNT REGISTER & LOGIN ROUTES =================
app.post('/api/auth/register', adminLoginLimiter, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!name || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, message: 'সঠিক নাম ও ইমেইল দিন।' });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে।' });
    }

    const exists = await pool.query('SELECT id FROM users WHERE LOWER(email) = $1', [email]);
    if (exists.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'এই ইমেইল দিয়ে ইতিমধ্যে অ্যাকাউন্ট খোলা আছে! লগইন করুন।' });
    }

    const pwHash = hashPassword(password);
    const created = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, plan) VALUES ($1, $2, $3, 'user', 'free') RETURNING id, name, email, role, plan`,
      [name, email, pwHash]
    );

    const user = created.rows[0];
    setUserAuthCookie(req, res, { id: user.id, name: user.name, email: user.email });
    res.json({ success: true, message: '🎉 অ্যাকাউন্ট রেজিস্ট্রেশন সফল হয়েছে!', user });
  } catch (e) {
    res.status(500).json({ success: false, message: 'রেজিস্ট্রেশন ব্যর্থ হয়েছে!' });
  }
});

app.post('/api/auth/login', adminLoginLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    const found = await pool.query('SELECT id, name, email, password_hash, role, plan FROM users WHERE LOWER(email) = $1', [email]);
    if (found.rows.length === 0 || !verifyPassword(password, found.rows[0].password_hash)) {
      return res.status(401).json({ success: false, message: '❌ ভুল ইমেইল অথবা পাসওয়ার্ড!' });
    }

    const u = found.rows[0];
    const user = { id: u.id, name: u.name || u.email.split('@')[0], email: u.email, role: u.role, plan: u.plan };
    setUserAuthCookie(req, res, { id: user.id, name: user.name, email: user.email });
    res.json({ success: true, message: '✅ লগইন সফল হয়েছে!', user });
  } catch (e) {
    res.status(500).json({ success: false, message: 'লগইন সমস্যা হয়েছে!' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'freesite_user_auth=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');
  res.json({ success: true, message: 'লগআউট সম্পন্ন।' });
});

app.get('/api/auth/me', async (req, res) => {
  const authUser = getLoggedInUser(req);
  if (!authUser) return res.json({ success: false, user: null, myStores: [] });
  try {
    const currentHost = (req.headers['x-forwarded-host'] || req.headers.host || 'techxzonee.shop')
      .split(',')[0].toLowerCase().split(':')[0].trim().replace(/^www\./, '');
    const myStores = await pool.query(
      `SELECT id, bot_name, subdomain, COALESCE(NULLIF(base_domain, ''), $2) AS base_domain, status, plan, created_at
       FROM whatsapp_bots WHERE user_id = $1 ORDER BY id DESC`,
      [authUser.id, currentHost]
    );
    res.json({ success: true, user: authUser, myStores: myStores.rows });
  } catch (e) {
    res.json({ success: true, user: authUser, myStores: [] });
  }
});

// ১. বট ও স্টোর তৈরি (লগইনকৃত অ্যাকাউন্টের সাথে যুক্ত)
app.post('/api/launch-bot-dashboard', async (req, res) => {
  try {
    const authUser = getLoggedInUser(req);
    if (!authUser) {
      return res.status(401).json({ success: false, message: '🔒 শপ তৈরি করতে প্রথমে অ্যাকাউন্ট লগইন বা রেজিস্টার করুন!' });
    }
    const { bot_type, bot_name, website_url, catalog_url, custom_info, subdomain, base_domain } = req.body;
    const cleanSub = String(subdomain || '').toLowerCase().trim().replace(/[^a-z0-9-]/g, '');

    if (!cleanSub || cleanSub.length < 2) {
      return res.status(400).json({ success: false, message: 'সঠিক শপ বা সাবডোমেইন নাম দিন (অন্তত ২ অক্ষর)।' });
    }
    if (['admin', 'api', 'dash', 'catalog', 'catalog-builder', 'ping', 'p', 'c'].includes(cleanSub)) {
      return res.status(400).json({ success: false, message: 'এই নামটি সিস্টেমের জন্য সংরক্ষিত। অন্য নাম দিন।' });
    }

    const dupCheck = await pool.query('SELECT id FROM whatsapp_bots WHERE LOWER(subdomain) = $1', [cleanSub]);
    if (dupCheck.rows.length > 0) {
      return res.status(400).json({ success: false, message: `⚠️ "${cleanSub}" নামটি ইতিমধ্যে ব্যবহৃত হয়েছে! অন্য একটি নাম দিন।` });
    }

    const currentHost = (req.headers['x-forwarded-host'] || req.headers.host || 'busness-bot.onrender.com')
      .toLowerCase().split(':')[0].trim().replace(/^www\./, '');
    const activeDomains = await getActivePlatformDomains();
    const allowedDomains = Array.from(new Set([currentHost, ...activeDomains].filter(Boolean)));
    const chosenDomain = String(base_domain || '').toLowerCase().trim();
    const finalDomain = allowedDomains.includes(chosenDomain) ? chosenDomain : currentHost;

    let finalPrompt = custom_info || '';
    let extractedProducts = [];

    if (bot_type === 'business_site' && website_url) {
      const siteKnowledge = await analyzeAndExtractWebsiteKnowledge(website_url);
      finalPrompt = siteKnowledge.description;
      extractedProducts = siteKnowledge.products || [];
    }

    if (bot_type === 'catalog_link' && catalog_url) {
      const match = catalog_url.match(/\/catalog\/([a-z0-9-]+)/i);
      const slug = match ? match[1] : catalog_url.trim();
      const catItems = await pool.query('SELECT * FROM store_catalog_items WHERE catalog_slug = $1', [slug]);
      const catInfo = await pool.query('SELECT store_name FROM store_catalogs WHERE catalog_slug = $1', [slug]);

      if (catItems.rows.length > 0) {
        finalPrompt = `${catInfo.rows[0]?.store_name || bot_name}-এর অফিসিয়াল ক্যাটালগ থেকে সংগৃহীত পণ্য ও সেবা।`;
        extractedProducts = catItems.rows.map(item => ({
          name: item.name,
          price: item.price,
          category: item.category,
          image_url: item.image_url || '',
          demo_images: item.demo_images || '',
          description: item.description,
          buy_link: ''
        }));
      }
    }

    const botInsert = await pool.query(
      `INSERT INTO whatsapp_bots (user_id, bot_name, website_url, system_prompt, bot_type, subdomain, base_domain, status, rate_limit_daily, plan)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'DISCONNECTED', 300, 'free') RETURNING id`,
      [authUser.id, bot_name || 'My Shop', website_url || catalog_url || '', finalPrompt, bot_type || 'catalog_link', cleanSub, finalDomain]
    );
    const botId = botInsert.rows[0].id;

    for (const p of extractedProducts) {
      await pool.query(
        `INSERT INTO bot_products (bot_id, name, price, category, image_url, demo_images, description, buy_link)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [botId, p.name, p.price || 0, p.category || 'General', p.image_url || '', p.demo_images || '', p.description || '', p.buy_link || '']
      );
    }

    await pool.query(
      `INSERT INTO hosted_websites (subdomain, base_domain, bot_id, theme_color)
       VALUES ($1, $2, $3, '#059669')
       ON CONFLICT (subdomain, base_domain) DO UPDATE SET bot_id = $3`,
      [cleanSub, finalDomain, botId]
    );

    addBotLog(botId, 'info', `🚀 শপ ও ড্যাশবোর্ড তৈরি সম্পন্ন!`);

    res.json({
      success: true,
      botId,
      shopUrl: `https://${finalDomain}/${cleanSub}`,
      dashboardUrl: `https://${finalDomain}/dash/${cleanSub}`
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// 🔒 সব ইউজার ড্যাশবোর্ড API ও পেয়ারিং কোড মালিকানা সুরক্ষা
app.use('/api/user', requireBotOwner);
app.use('/api/request-pairing-code', requireBotOwner);

// ২. ড্যাশবোর্ডের লাইভ লগ ও স্ট্যাটস
app.get('/api/user/bot-logs', async (req, res) => {
  const botId = Number(req.query.botId);
  if (!botId) return res.json({ success: false });
  const logs = botLiveLogs.get(botId) || [];
  let stats = { tokens: 0, requests: 0 };
  try {
    const s = await pool.query('SELECT tokens_used, requests_today FROM whatsapp_bots WHERE id = $1', [botId]);
    if (s.rows.length > 0) {
      stats.tokens = s.rows[0].tokens_used || 0;
      stats.requests = s.rows[0].requests_today || 0;
    }
  } catch (e) {}
  res.json({ success: true, logs, stats });
});

app.post('/api/user/clear-logs', (req, res) => {
  const botId = Number(req.body.botId);
  if (botLiveLogs.has(botId)) {
    botLiveLogs.set(botId, [{ time: new Date().toLocaleTimeString('en-US', { hour12: false }), type: 'info', message: '🧹 কনসোল লগ সম্পূর্ণ পরিষ্কার করা হয়েছে।' }]);
  }
  res.json({ success: true, message: 'লগ মুছে ফেলা হয়েছে।' });
});

app.post('/api/user/update-bot-settings', async (req, res) => {
  try {
    const { botId, bot_name, alert_phone, knowledge_source, bot_type, system_prompt, delivery_inside, delivery_outside } = req.body;
    await pool.query(
      `UPDATE whatsapp_bots 
       SET bot_name = $1, alert_phone = $2, knowledge_source = $3, bot_type = $4, system_prompt = $5, delivery_inside = $6, delivery_outside = $7 
       WHERE id = $8`,
      [bot_name, alert_phone, knowledge_source || 'catalog', bot_type, system_prompt, parseInt(delivery_inside, 10) || 70, parseInt(delivery_outside, 10) || 130, botId]
    );
    addBotLog(botId, 'success', '⚙️ বটের তথ্য ও নির্দেশিকা সফলভাবে আপডেট হয়েছে!');
    res.json({ success: true, message: '✅ বটের তথ্য সফলভাবে আপডেট হয়েছে!' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/user/claim-trial', async (req, res) => {
  try {
    const { botId } = req.body;
    const check = await pool.query('SELECT trial_used FROM whatsapp_bots WHERE id = $1', [botId]);
    if (check.rows.length === 0) return res.status(404).json({ success: false, message: 'বট পাওয়া যায়নি!' });

    if (check.rows[0].trial_used) {
      return res.status(400).json({
        success: false,
        message: '⚠️ আপনার ১০ দিনের ফ্রি ট্রায়াল ইতিমধ্যে শেষ হয়েছে! প্রিমিয়াম আপগ্রেড করুন।'
      });
    }

    await pool.query(
      `UPDATE whatsapp_bots 
       SET trial_used = TRUE, plan = 'trial', package_name = '10 Days Trial',
           trial_expires_at = NOW() + INTERVAL '10 days', rate_limit_daily = 1500 
       WHERE id = $1`,
      [botId]
    );

    addBotLog(botId, 'success', '🎉 ১০ দিনের ফ্রি ট্রায়াল সক্রিয় করা হয়েছে!');
    res.json({ success: true, message: '🎉 অভিনন্দন! আপনার ১০ দিনের ফ্রি ট্রায়াল সক্রিয় হয়েছে!' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post('/api/user/reanalyze-site', async (req, res) => {
  try {
    const { botId, website_url } = req.body;
    const botRes = await pool.query('SELECT gemini_api_key, plan, trial_used, trial_expires_at, expires_at FROM whatsapp_bots WHERE id = $1', [botId]);
    if (botRes.rows.length === 0) return res.status(404).json({ success: false, message: 'বট পাওয়া যায়নি' });

    const bot = botRes.rows[0];
    const isPremium = bot.plan === 'premium' && (!bot.expires_at || new Date(bot.expires_at) > new Date());
    const isTrialActive = bot.plan === 'trial' && bot.trial_expires_at && new Date(bot.trial_expires_at) > new Date();

    if (!isPremium && !isTrialActive) {
      return res.status(403).json({
        success: false,
        requires_upgrade: true,
        trial_used: bot.trial_used,
        message: bot.trial_used
          ? '🔒 আপনার ১০ দিনের ট্রায়াল শেষ হয়েছে। লাইভ ওয়েবসাইট অ্যানালাইজ করতে প্রিমিয়াম আপগ্রেড করুন!'
          : '🔒 এটি একটি প্রিমিয়াম ফিচার! ১০ দিনের ফ্রি ট্রায়াল চালু করুন অথবা প্রিমিয়াম নিন।'
      });
    }

    addBotLog(botId, 'info', `🌐 এআই দিয়ে ওয়েবসাইট রি-অ্যানালাইসিস শুরু হচ্ছে: ${website_url}`);
    const knowledge = await analyzeAndExtractWebsiteKnowledge(website_url, bot.gemini_api_key || null);

    await pool.query(`UPDATE whatsapp_bots SET website_url = $1, system_prompt = $2 WHERE id = $3`, [website_url, knowledge.description, botId]);
    await pool.query('DELETE FROM bot_products WHERE bot_id = $1', [botId]);
    for (const p of knowledge.products) {
      await pool.query(
        `INSERT INTO bot_products (bot_id, name, price, category, description, buy_link) VALUES ($1, $2, $3, $4, $5, $6)`,
        [botId, p.name, p.price || 0, p.category || 'General', p.description || '', p.buy_link || '']
      );
    }

    addBotLog(botId, 'success', `✅ ওয়েবসাইট অ্যানালাইসিস সম্পন্ন: ${knowledge.businessType}`);
    res.json({ success: true, message: `🎉 ওয়েবসাইট অ্যানালাইসিস সম্পন্ন! ক্যাটাগরি: ${knowledge.businessType}` });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/user/test-chat', async (req, res) => {
  try {
    const { botId, message } = req.body;
    const botRes = await pool.query('SELECT * FROM whatsapp_bots WHERE id = $1', [botId]);
    if (botRes.rows.length === 0) return res.status(404).json({ success: false });

    const reply = await handleDynamicCustomerMessage(botRes.rows[0], 'TEST_WEB_USER', message, null);
    res.json({ success: true, reply });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.get('/api/user/products', async (req, res) => {
  try {
    const botId = Number(req.query.botId);
    const result = await pool.query('SELECT * FROM bot_products WHERE bot_id = $1 ORDER BY id DESC', [botId]);
    res.json({ success: true, products: result.rows });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

async function uploadToImgBB(base64Image, customImgbbKey = null) {
  try {
    const apiKey = customImgbbKey || process.env.IMGBB_API_KEY || '6d7fde81f9936bd5cdb2b515c496a4f6';
    const cleanBase64 = base64Image.replace(/^data:image\/[a-z]+;base64,/, '');
    const params = new URLSearchParams();
    params.append('image', cleanBase64);

    const response = await fetch(`https://api.imgbb.com/1/upload?key=${apiKey}`, { method: 'POST', body: params });
    const resData = await response.json();
    if (resData.success) return resData.data.url;
  } catch (err) {
    console.error('[IMGBB UPLOAD ERROR]:', err.message);
  }
  return base64Image;
}

app.post('/api/user/products/add', async (req, res) => {
  try {
    const { botId, name, price, regular_price, category, description, buy_link, image_url, demo_images } = req.body;
    const botRow = await pool.query('SELECT subdomain, base_domain, imgbb_api_key FROM whatsapp_bots WHERE id = $1', [botId]);
    if (botRow.rows.length === 0) return res.status(404).json({ success: false, message: 'বট পাওয়া যায়নি' });

    let finalImgUrl = image_url || '';
    if (finalImgUrl && finalImgUrl.startsWith('data:image')) {
      finalImgUrl = await uploadToImgBB(finalImgUrl, botRow.rows[0].imgbb_api_key);
    }

    const currentHost = (req.headers['x-forwarded-host'] || req.headers.host || 'busness-bot.onrender.com')
      .toLowerCase().split(':')[0].trim().replace(/^www\./, '');
    const sub = botRow.rows[0].subdomain || 'shop';
    const dom = botRow.rows[0].base_domain || currentHost;
    const safeBuyLink = sanitizeUrl(buy_link);

    const inserted = await pool.query(
      `INSERT INTO bot_products (bot_id, name, price, regular_price, category, description, buy_link, image_url, demo_images)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
      [botId, name, parseFloat(price) || 0, regular_price ? parseFloat(regular_price) : null, category || 'General', description || '', safeBuyLink, finalImgUrl, demo_images || '']
    );

    const prodId = inserted.rows[0].id;
    const singleProdUrl = `https://${dom}/${sub}/p/${prodId}`;
    await pool.query("UPDATE bot_products SET buy_link = COALESCE(NULLIF($1, ''), $2) WHERE id = $3", [safeBuyLink, singleProdUrl, prodId]);

    addBotLog(botId, 'success', `📦 নতুন পণ্য যোগ হয়েছে: ${name} (৳${price})`);
    res.json({ success: true, message: 'প্রোডাক্ট সফলভাবে যুক্ত হয়েছে!', product_url: singleProdUrl });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/user/products/update', async (req, res) => {
  try {
    const { botId, productId, name, price, regular_price, category, description, buy_link, image_url, demo_images } = req.body;
    const botRow = await pool.query('SELECT imgbb_api_key FROM whatsapp_bots WHERE id = $1', [botId]);

    let finalImgUrl = image_url || '';
    if (finalImgUrl && finalImgUrl.startsWith('data:image')) {
      finalImgUrl = await uploadToImgBB(finalImgUrl, botRow.rows[0]?.imgbb_api_key);
    }

    await pool.query(
      `UPDATE bot_products 
       SET name = $1, price = $2, regular_price = $3, category = $4, description = $5, 
           buy_link = COALESCE(NULLIF($6, ''), buy_link),
           image_url = COALESCE(NULLIF($7, ''), image_url),
           demo_images = COALESCE(NULLIF($8, ''), demo_images)
       WHERE id = $9 AND bot_id = $10`,
      [name, parseFloat(price) || 0, regular_price ? parseFloat(regular_price) : null, category, description, sanitizeUrl(buy_link), finalImgUrl, demo_images || '', productId, botId]
    );

    addBotLog(botId, 'success', `✏️ পণ্য আপডেট সম্পন্ন: ${name}`);
    res.json({ success: true, message: '✅ পণ্য সফলভাবে আপডেট হয়েছে!' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/user/products/delete', async (req, res) => {
  try {
    const { botId, productId } = req.body;
    await pool.query('DELETE FROM bot_products WHERE id = $1 AND bot_id = $2', [productId, botId]);
    addBotLog(botId, 'info', `🗑️ প্রোডাক্ট মুছে ফেলা হয়েছে (ID: #${productId})`);
    res.json({ success: true, message: 'প্রোডাক্ট মুছে ফেলা হয়েছে!' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/user/submit-payment', async (req, res) => {
  try {
    const { botId, method, sender, trxId } = req.body;
    if (!trxId || !sender) return res.status(400).json({ success: false, message: 'সব তথ্য দিন।' });

    await pool.query(
      `INSERT INTO payments (bot_id, payment_method, sender_number, trx_id, amount, status)
       VALUES ($1, $2, $3, $4, 300, 'PENDING')`,
      [botId, method, sender, trxId]
    );
    addBotLog(botId, 'info', `💳 ৳৩০০ (${method}) পেমেন্ট জমা হয়েছে (TrxID: ${trxId}) — পেন্ডিং`);
    res.json({ success: true, message: '✅ পেমেন্ট তথ্য জমা হয়েছে! অ্যাডমিন যাচাই করে প্রিমিয়াম সক্রিয় করবেন।' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/user/update-api-key', async (req, res) => {
  try {
    const { botId, apiKey } = req.body;
    await pool.query('UPDATE whatsapp_bots SET gemini_api_key = $1 WHERE id = $2', [apiKey ? apiKey.trim() : null, botId]);
    addBotLog(botId, 'success', apiKey ? '🔑 নতুন Gemini API Key যুক্ত হয়েছে।' : 'ℹ️ প্ল্যাটফর্ম ডিফল্ট Key সক্রিয়।');
    res.json({ success: true, message: '✅ API Key সংরক্ষিত হয়েছে!' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/request-pairing-code', async (req, res) => {
  try {
    const { botId, phone } = req.body;
    const bId = Number(botId);
    let cleanPhone = String(phone || '').replace(/[^0-9]/g, '');
    if (cleanPhone.startsWith('01') && cleanPhone.length === 11) cleanPhone = '88' + cleanPhone;

    if (!cleanPhone || cleanPhone.length < 10) {
      return res.status(400).json({ success: false, message: 'সঠিক মোবাইল নম্বর দিন (যেমন: 88014...)' });
    }

    let botObj = activeSockets.get(bId);
    if (botObj && botObj.sock) {
      try {
        botObj.sock.ws?.close();
        botObj.sock.ev?.removeAllListeners();
      } catch (_) {}
      activeSockets.delete(bId);
    }

    await pool.query('DELETE FROM whatsapp_sessions WHERE bot_id = $1', [bId]);
    await pool.query("UPDATE whatsapp_bots SET phone_number = $1, status = 'DISCONNECTED' WHERE id = $2", [cleanPhone, bId]);

    await startTenantBot(bId);
    await delay(3000);

    botObj = activeSockets.get(bId);
    if (botObj && botObj.sock) {
      try {
        const rawCode = await botObj.sock.requestPairingCode(cleanPhone);
        const formattedCode = rawCode?.match(/.{1,4}/g)?.join('-') || rawCode;
        addBotLog(bId, 'info', `📲 নতুন পেয়ারিং কোড তৈরি হয়েছে: ${formattedCode}`);
        return res.json({ success: true, pairingCode: formattedCode });
      } catch (pairErr) {
        return res.status(500).json({ success: false, message: 'হোয়াটসঅ্যাপ থেকে কোড তৈরিতে সমস্যা: ' + pairErr.message });
      }
    }

    return res.status(500).json({ success: false, message: 'সার্ভারে সকেট স্টার্ট হতে পারেনি, আবার চেষ্টা করুন।' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/user/update-theme', async (req, res) => {
  try {
    const { botId, themeColor } = req.body;
    if (!/^#[0-9a-fA-F]{3,6}$/.test(themeColor || '')) {
      return res.status(400).json({ success: false });
    }
    await pool.query('UPDATE hosted_websites SET theme_color = $1 WHERE bot_id = $2', [themeColor, botId]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false });
  }
});

// ================= SUPER ADMIN AUTHENTICATION & PROTECTED ENDPOINTS =================

function parseAdminCookie(req) {
  const rawCookies = req.headers.cookie || '';
  const match = rawCookies.match(/freesite_admin_auth=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

async function getMasterAdminPassword() {
  const dbPass = await pool.query("SELECT value FROM admin_settings WHERE key = 'admin_password'");
  return (dbPass.rows[0]?.value || process.env.ADMIN_PASSWORD || '@1234567890@sojib@1234567890@sojib#').trim();
}

async function checkAdminAuth(req, res, next) {
  try {
    const cookiePass = parseAdminCookie(req);
    const inputPass = req.headers['x-admin-password'] || req.query.password || cookiePass;
    const masterPassword = await getMasterAdminPassword();

    if (inputPass && safeCompare(String(inputPass).trim(), masterPassword)) {
      return next();
    }
    return res.status(401).json({ success: false, message: '🔒 অননুমোদিত অ্যাক্সেস! সঠিক অ্যাডমিন পাসওয়ার্ড দিন।' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Auth Verification Error' });
  }
}

app.post('/api/admin/login', adminLoginLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    const masterPassword = await getMasterAdminPassword();

    if (password && safeCompare(String(password).trim(), masterPassword)) {
      const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';
      const cookieFlags = [
        `freesite_admin_auth=${encodeURIComponent(String(password).trim())}`,
        'Path=/',
        'Max-Age=86400',
        'HttpOnly',
        'SameSite=Lax'
      ];
      if (isHttps) cookieFlags.push('Secure');
      res.setHeader('Set-Cookie', cookieFlags.join('; '));
      return res.json({ success: true, message: 'লগইন সফল!' });
    }
    return res.status(401).json({ success: false, message: '❌ ভুল পাসওয়ার্ড! আবার চেষ্টা করুন।' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/admin/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'freesite_admin_auth=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');
  res.json({ success: true, message: 'লগআউট সম্পন্ন।' });
});

app.get('/admin', async (req, res) => {
  try {
    const cookiePass = parseAdminCookie(req);
    const masterPassword = await getMasterAdminPassword();

    if (cookiePass && safeCompare(cookiePass.trim(), masterPassword)) {
      return res.sendFile(path.join(__dirname, 'public', 'admin.html'));
    }
  } catch (e) {}

  res.send(`<!DOCTYPE html>
<html lang="bn">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Super Admin Security — FreeSite</title>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=Hind+Siliguri:wght@400;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css">
  <style>
    *{box-sizing:border-box;margin:0;padding:0;font-family:'Plus Jakarta Sans','Hind Siliguri',sans-serif}
    body{
      background:#0f172a;
      background-image:radial-gradient(at 0% 0%,rgba(16,185,129,.18) 0,transparent 45%),radial-gradient(at 100% 100%,rgba(14,165,233,.14) 0,transparent 45%);
      color:#f8fafc;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;
    }
    .login-card{
      max-width:420px;width:100%;background:rgba(30,41,59,.72);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
      border:1px solid rgba(255,255,255,.14);border-radius:24px;padding:34px 28px;text-align:center;
      box-shadow:0 25px 50px -12px rgba(0,0,0,.55);
    }
    .icon-box{
      width:68px;height:68px;border-radius:20px;background:rgba(16,185,129,.16);border:1px solid rgba(16,185,129,.45);
      display:flex;align-items:center;justify-content:center;margin:0 auto 20px;color:#10b981;font-size:32px;
    }
    h2{font-size:22px;font-weight:800;margin-bottom:6px}
    p{font-size:13px;color:#94a3b8;margin-bottom:22px;line-height:1.5}
    input{
      width:100%;padding:14px 18px;background:rgba(15,23,42,.65);border:1px solid rgba(255,255,255,.16);
      border-radius:14px;color:#fff;font-size:15px;outline:none;margin-bottom:14px;text-align:center;
    }
    input:focus{border-color:#10b981;box-shadow:0 0 0 4px rgba(16,185,129,.22)}
    button{
      width:100%;padding:14px;background:linear-gradient(135deg,#059669,#047857);color:#fff;border:none;
      border-radius:14px;font-size:15px;font-weight:800;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px;
    }
    #errMsg{color:#fca5a5;font-size:12px;margin-top:12px;display:none;font-weight:700}
  </style>
</head>
<body>
  <div class="login-card">
    <div class="icon-box"><i class="ti ti-shield-lock"></i></div>
    <h2>সুপার অ্যাডমিন সিকিউরিটি</h2>
    <p>মাস্টার কন্ট্রোল কনসোলে প্রবেশ করতে আপনার সিক্রেট পাসওয়ার্ড দিন</p>
    <input type="password" id="adminPassInput" placeholder="অ্যাডমিন পাসওয়ার্ড লিখুন" onkeypress="if(event.key==='Enter') verifyAdminLogin()">
    <button id="btnLogin" onclick="verifyAdminLogin()"><i class="ti ti-key"></i> আনলক করুন</button>
    <div id="errMsg"></div>
  </div>
  <script>
    async function verifyAdminLogin(){
      const pass=document.getElementById('adminPassInput').value.trim();
      if(!pass)return alert('পাসওয়ার্ড লিখুন!');
      const btn=document.getElementById('btnLogin');btn.innerText='যাচাই হচ্ছে...';
      try{
        const res=await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pass})});
        const data=await res.json();
        if(data.success)window.location.reload();
        else{const e=document.getElementById('errMsg');e.style.display='block';e.innerText=data.message;}
      }catch(e){alert('সার্ভার কানেকশন সমস্যা!');}
      finally{btn.innerHTML='<i class="ti ti-key"></i> আনলক করুন';}
    }
  </script>
</body>
</html>`);
});

app.get('/api/admin/overview', checkAdminAuth, async (req, res) => {
  try {
    const bots = await pool.query('SELECT * FROM whatsapp_bots ORDER BY id DESC');
    const servers = await pool.query('SELECT * FROM worker_servers ORDER BY id DESC');
    const payments = await pool.query('SELECT p.*, b.bot_name FROM payments p LEFT JOIN whatsapp_bots b ON p.bot_id = b.id ORDER BY p.id DESC');
    const settings = await pool.query("SELECT key, value FROM admin_settings WHERE key != 'admin_password'");
    const domains = await pool.query('SELECT * FROM platform_domains ORDER BY id DESC');
    res.json({ success: true, bots: bots.rows, servers: servers.rows, payments: payments.rows, settings: settings.rows, domains: domains.rows });
  } catch (e) { res.status(500).json({ success: false }); }
});

app.get('/api/admin/domains', checkAdminAuth, async (req, res) => {
  try {
    const domains = await pool.query('SELECT * FROM platform_domains ORDER BY id DESC');
    res.json({ success: true, domains: domains.rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/domains', checkAdminAuth, async (req, res) => {
  try {
    let { domain_name, notes } = req.body;
    domain_name = String(domain_name || '').toLowerCase().trim()
      .replace(/^https?:\/\//, '')
      .replace(/^www\./, '')
      .split('/')[0]
      .split(':')[0];

    if (!domain_name || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain_name)) {
      return res.status(400).json({ success: false, message: 'সঠিক ডোমেইন নাম দিন (যেমন: myshopbd.com)' });
    }

    const inserted = await pool.query(
      `INSERT INTO platform_domains (domain_name, is_active, notes)
       VALUES ($1, TRUE, $2)
       ON CONFLICT (domain_name) DO UPDATE SET is_active = TRUE, notes = COALESCE(NULLIF($2, ''), platform_domains.notes)
       RETURNING *`,
      [domain_name, notes || '']
    );

    lastDomainFetch = 0;
    res.json({
      success: true,
      message: `✅ ডোমেইন "${domain_name}" যুক্ত হয়েছে! এখন https://${domain_name}/myshop এ শপ ওপেন হবে।`,
      domain: inserted.rows[0]
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/admin/domains/toggle', checkAdminAuth, async (req, res) => {
  try {
    const { id } = req.body;
    await pool.query('UPDATE platform_domains SET is_active = NOT is_active WHERE id = $1', [id]);
    lastDomainFetch = 0;
    res.json({ success: true, message: '✅ ডোমেইন স্ট্যাটাস আপডেট হয়েছে!' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/domains/delete', checkAdminAuth, async (req, res) => {
  try {
    const { id } = req.body;
    await pool.query('DELETE FROM platform_domains WHERE id = $1', [id]);
    lastDomainFetch = 0;
    res.json({ success: true, message: '🗑️ ডোমেইন মুছে ফেলা হয়েছে!' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/admin/applications', checkAdminAuth, async (req, res) => {
  try {
    const apps = await pool.query('SELECT id, app_name, app_id, permissions, status, request_count, last_access_at, created_at FROM api_applications ORDER BY id DESC');
    res.json({ success: true, connected_applications: apps.rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/create-application', checkAdminAuth, async (req, res) => {
  try {
    const { app_name } = req.body;
    if (!app_name) return res.status(400).json({ success: false, message: 'অ্যাপ নাম দিন!' });

    const appId = 'app_' + crypto.randomBytes(6).toString('hex');
    const rawApiKey = 'fs_live_' + crypto.randomBytes(16).toString('hex');
    const rawSecretKey = 'fs_sec_' + crypto.randomBytes(24).toString('hex');

    const apiKeyHash = crypto.createHash('sha256').update(rawApiKey).digest('hex');
    const secretKeyHash = crypto.createHash('sha256').update(rawSecretKey).digest('hex');

    await pool.query(
      `INSERT INTO api_applications (app_name, app_id, api_key_hash, secret_key_hash, status)
       VALUES ($1, $2, $3, $4, 'active')`,
      [app_name.trim(), appId, apiKeyHash, secretKeyHash]
    );

    res.json({
      success: true,
      credentials: { app_id: appId, api_key: rawApiKey, secret_key: rawSecretKey }
    });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/revoke-application', checkAdminAuth, async (req, res) => {
  try {
    const { app_id } = req.body;
    await pool.query("UPDATE api_applications SET status = 'revoked' WHERE app_id = $1", [app_id]);
    res.json({ success: true, message: 'অ্যাপ অ্যাক্সেস বাতিল করা হয়েছে।' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/set-max-bots-limit', checkAdminAuth, async (req, res) => {
  try {
    const { limit } = req.body;
    const numLimit = parseInt(limit, 10) || 4;
    await pool.query("INSERT INTO admin_settings (key, value) VALUES ('max_bots_per_server', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [String(numLimit)]);
    await pool.query('UPDATE worker_servers SET max_capacity = $1', [numLimit]);
    res.json({ success: true, message: `✅ সার্ভার প্রতি সর্বোচ্চ বটের ক্যাপাসিটি ${numLimit} সেট করা হয়েছে!` });
  } catch (e) { res.status(500).json({ success: false }); }
});

app.post('/api/admin/approve-payment', checkAdminAuth, async (req, res) => {
  try {
    const { paymentId, days, dailyLimit, packageName, amount } = req.body;
    const payRes = await pool.query('SELECT bot_id FROM payments WHERE id = $1', [paymentId]);
    if (payRes.rows.length === 0) return res.status(404).json({ success: false });
    const botId = payRes.rows[0].bot_id;

    const validDays = parseInt(days, 10) || 30;
    const limit = parseInt(dailyLimit, 10) || 3000;
    const pkg = packageName || 'Standard Premium';

    await pool.query(
      `UPDATE payments SET status = 'APPROVED', amount = $1, approved_days = $2, custom_limit = $3 WHERE id = $4`,
      [parseFloat(amount) || 300, validDays, limit, paymentId]
    );

    await pool.query(
      `UPDATE whatsapp_bots SET plan = 'premium', package_name = $1, rate_limit_daily = $2, expires_at = NOW() + ($3 || ' days')::INTERVAL WHERE id = $4`,
      [pkg, limit, validDays, botId]
    );

    addBotLog(botId, 'success', `🎉 অভিনন্দন! অ্যাডমিন আপনার ${validDays} দিনের প্রিমিয়াম (${pkg}) সক্রিয় করেছেন!`);
    res.json({ success: true, message: `✅ সফল! বটটি ${validDays} দিন এবং ডেইলি ${limit} রিকোয়েস্টে প্রিমিয়াম করা হয়েছে!` });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/admin/update-bot-limit', checkAdminAuth, async (req, res) => {
  try {
    const { botId, newLimit } = req.body;
    await pool.query('UPDATE whatsapp_bots SET rate_limit_daily = $1 WHERE id = $2', [parseInt(newLimit, 10) || 300, botId]);
    res.json({ success: true, message: '✅ লিমিট আপডেট সম্পন্ন!' });
  } catch (e) { res.status(500).json({ success: false }); }
});

app.post('/api/admin/assign-bot-keys', checkAdminAuth, async (req, res) => {
  try {
    const { botId, geminiKey, imgbbKey } = req.body;
    await pool.query(
      `UPDATE whatsapp_bots 
       SET gemini_api_key = COALESCE(NULLIF($1, ''), gemini_api_key),
           imgbb_api_key = COALESCE(NULLIF($2, ''), imgbb_api_key)
       WHERE id = $3`,
      [geminiKey ? geminiKey.trim() : null, imgbbKey ? imgbbKey.trim() : null, botId]
    );

    addBotLog(botId, 'success', `👑 অ্যাডমিন এই বটের জন্য ডেডিকেটেড এআই ও ইমেজ কী অ্যাসাইন করেছেন!`);
    res.json({ success: true, message: '✅ ইউজারটির জন্য ডেডিকেটেড কী সফলভাবে সেট করা হয়েছে!' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/admin/update-payment-numbers', checkAdminAuth, async (req, res) => {
  try {
    const { bkash, nagad, rocket } = req.body;
    await pool.query("INSERT INTO admin_settings (key, value) VALUES ('bkash_no', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [bkash]);
    await pool.query("INSERT INTO admin_settings (key, value) VALUES ('nagad_no', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [nagad]);
    await pool.query("INSERT INTO admin_settings (key, value) VALUES ('rocket_no', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [rocket]);
    res.json({ success: true, message: '✅ পেমেন্ট নম্বর সংরক্ষিত হয়েছে!' });
  } catch (e) { res.status(500).json({ success: false }); }
});

app.post('/api/admin/rebalance-servers', checkAdminAuth, async (req, res) => {
  try {
    const servers = await pool.query('SELECT id, max_capacity FROM worker_servers WHERE is_active = TRUE ORDER BY id ASC');
    if (servers.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'কোনো ওয়ার্কার সার্ভার নেই!' });
    }
    const bots = await pool.query('SELECT id FROM whatsapp_bots ORDER BY id ASC');
    const srvIds = servers.rows.map(s => s.id);

    for (let i = 0; i < bots.rows.length; i++) {
      const assignedSrv = srvIds[i % srvIds.length];
      await pool.query('UPDATE whatsapp_bots SET server_id = $1 WHERE id = $2', [assignedSrv, bots.rows[i].id]);
    }

    res.json({ success: true, message: `🎉 মোট ${bots.rows.length} টি বট ${srvIds.length} টি সার্ভারে সমানভাবে ভাগ করা হয়েছে!` });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/admin/smart-reset', checkAdminAuth, async (req, res) => {
  try {
    for (const [, bObj] of activeSockets.entries()) {
      try {
        if (bObj.sock) {
          bObj.sock.ws?.close();
          bObj.sock.ev?.removeAllListeners();
        }
      } catch (_) {}
    }
    activeSockets.clear();
    botChatHistories.clear();

    for (const [, logs] of botLiveLogs.entries()) {
      if (logs.length > 10) logs.length = 10;
    }

    const bots = await pool.query("SELECT id FROM whatsapp_bots WHERE status = 'CONNECTED'");
    for (const row of bots.rows) {
      await delay(800);
      startTenantBot(row.id);
    }

    res.json({
      success: true,
      message: `⚡ স্মার্ট রিসেট সম্পন্ন! মেমরি ফ্রেশ হয়েছে এবং সক্রিয় ${bots.rows.length}টি বট পুনরায় কানেক্ট হয়েছে!`
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 🏓 পিং ও সার্ভার হেলথ মনিটর
app.get('/ping', async (req, res) => {
  const start = Date.now();
  let dbStatus = 'CONNECTED';
  let dbPing = 0;
  let totalBots = 0;
  let connectedBots = 0;

  try {
    const dbStart = Date.now();
    await pool.query('SELECT 1');
    dbPing = Date.now() - dbStart;

    const botStats = await pool.query("SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE status = 'CONNECTED') as connected FROM whatsapp_bots");
    totalBots = parseInt(botStats.rows[0]?.total || 0, 10);
    connectedBots = parseInt(botStats.rows[0]?.connected || 0, 10);
  } catch (err) {
    dbStatus = 'ERROR: ' + err.message;
  }

  const uptimeSec = Math.floor(process.uptime());
  const days = Math.floor(uptimeSec / 86400);
  const hours = Math.floor((uptimeSec % 86400) / 3600);
  const minutes = Math.floor((uptimeSec % 3600) / 60);
  const seconds = uptimeSec % 60;
  const uptimeStr = (days > 0 ? days + ' দিন ' : '') + hours + ' ঘণ্টা ' + minutes + ' মিনিট ' + seconds + ' সেকেন্ড';

  const mem = process.memoryUsage();
  res.status(200).json({
    status: 'ONLINE',
    statusCode: 200,
    message: '🚀 FreeSite Master Server is healthy and running smoothly!',
    dhaka_time: new Date().toLocaleString('en-US', { timeZone: 'Asia/Dhaka' }),
    response_latency: (Date.now() - start) + ' ms',
    server_health: {
      uptime: uptimeStr,
      node_version: process.version,
      platform: process.platform,
      memory_usage: {
        rss: (mem.rss / 1024 / 1024).toFixed(1) + ' MB',
        heapUsed: (mem.heapUsed / 1024 / 1024).toFixed(1) + ' MB',
        heapTotal: (mem.heapTotal / 1024 / 1024).toFixed(1) + ' MB'
      }
    },
    database_health: { status: dbStatus, latency: dbPing + ' ms' },
    whatsapp_engine: {
      live_active_sockets: activeSockets.size,
      connected_bots_in_db: connectedBots,
      total_created_bots: totalBots
    }
  });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// সার্ভার চালু ও স্কিমা ইনিশিয়ালাইজেশন
app.listen(PORT, '0.0.0.0', async () => {
  console.log(`[INFO]: 🚀 FreeSite Master Node running on port ${PORT}`);
  try {
    await initializeDatabase();
    await initializeProductCloudSystem();

    await pool.query(`
      CREATE TABLE IF NOT EXISTS platform_domains (
        id SERIAL PRIMARY KEY,
        domain_name VARCHAR(255) UNIQUE NOT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS custom_catalogs (
        id SERIAL PRIMARY KEY,
        catalog_slug VARCHAR(100) UNIQUE,
        store_name VARCHAR(150),
        items_json JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        bot_id INT REFERENCES whatsapp_bots(id) ON DELETE CASCADE,
        payment_method VARCHAR(50),
        sender_number VARCHAR(50),
        trx_id VARCHAR(100) UNIQUE,
        amount NUMERIC(10, 2),
        status VARCHAR(30) DEFAULT 'PENDING',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS admin_settings (
        key VARCHAR(100) PRIMARY KEY,
        value TEXT
      );
      CREATE TABLE IF NOT EXISTS bot_orders (
        id SERIAL PRIMARY KEY,
        bot_id INT REFERENCES whatsapp_bots(id) ON DELETE CASCADE,
        customer_phone VARCHAR(50),
        customer_name VARCHAR(150),
        shipping_address TEXT,
        product_details TEXT,
        status VARCHAR(50) DEFAULT 'NEW',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS store_catalogs (
        id SERIAL PRIMARY KEY,
        catalog_slug VARCHAR(100) UNIQUE NOT NULL,
        store_name VARCHAR(150) NOT NULL,
        admin_pin VARCHAR(20) DEFAULT '1234',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS store_catalog_items (
        id SERIAL PRIMARY KEY,
        catalog_slug VARCHAR(100) REFERENCES store_catalogs(catalog_slug) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        price NUMERIC(10, 2) NOT NULL,
        category VARCHAR(100),
        image_url TEXT,
        demo_images TEXT,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS name VARCHAR(150);
      ALTER TABLE whatsapp_bots ADD COLUMN IF NOT EXISTS rate_limit_daily INT DEFAULT 300;
      ALTER TABLE whatsapp_bots ADD COLUMN IF NOT EXISTS plan VARCHAR(30) DEFAULT 'free';
      ALTER TABLE whatsapp_bots ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;
      ALTER TABLE whatsapp_bots ADD COLUMN IF NOT EXISTS package_name VARCHAR(100) DEFAULT 'Free Trial';
      ALTER TABLE whatsapp_bots ADD COLUMN IF NOT EXISTS trial_used BOOLEAN DEFAULT FALSE;
      ALTER TABLE whatsapp_bots ADD COLUMN IF NOT EXISTS trial_expires_at TIMESTAMP;
      ALTER TABLE whatsapp_bots ADD COLUMN IF NOT EXISTS subdomain VARCHAR(100);
      ALTER TABLE whatsapp_bots ADD COLUMN IF NOT EXISTS base_domain VARCHAR(150);
      ALTER TABLE whatsapp_bots ADD COLUMN IF NOT EXISTS bot_type VARCHAR(50) DEFAULT 'catalog_link';
      ALTER TABLE whatsapp_bots ADD COLUMN IF NOT EXISTS tokens_used INT DEFAULT 0;
      ALTER TABLE whatsapp_bots ADD COLUMN IF NOT EXISTS requests_today INT DEFAULT 0;
      ALTER TABLE whatsapp_bots ADD COLUMN IF NOT EXISTS gemini_api_key TEXT;
      ALTER TABLE whatsapp_bots ADD COLUMN IF NOT EXISTS imgbb_api_key TEXT;
      ALTER TABLE whatsapp_bots ADD COLUMN IF NOT EXISTS alert_phone VARCHAR(50);
      ALTER TABLE whatsapp_bots ADD COLUMN IF NOT EXISTS knowledge_source VARCHAR(30) DEFAULT 'catalog';

      ALTER TABLE payments ADD COLUMN IF NOT EXISTS approved_days INT DEFAULT 30;
      ALTER TABLE payments ADD COLUMN IF NOT EXISTS custom_limit INT DEFAULT 3000;

      ALTER TABLE hosted_websites ADD COLUMN IF NOT EXISTS bot_id INT REFERENCES whatsapp_bots(id) ON DELETE CASCADE;
      ALTER TABLE hosted_websites ADD COLUMN IF NOT EXISTS theme_color VARCHAR(30) DEFAULT '#059669';

      ALTER TABLE store_catalog_items ADD COLUMN IF NOT EXISTS image_url TEXT;
      ALTER TABLE store_catalog_items ADD COLUMN IF NOT EXISTS demo_images TEXT;
      ALTER TABLE store_catalogs ADD COLUMN IF NOT EXISTS admin_pin VARCHAR(20) DEFAULT '1234';
      ALTER TABLE store_catalogs ADD COLUMN IF NOT EXISTS user_id INT REFERENCES users(id) ON DELETE CASCADE;
      ALTER TABLE bot_products ADD COLUMN IF NOT EXISTS image_url TEXT;
      ALTER TABLE bot_products ADD COLUMN IF NOT EXISTS regular_price NUMERIC(10, 2);
      ALTER TABLE bot_products ADD COLUMN IF NOT EXISTS demo_images TEXT;
    `);

    await pool.query(`
      INSERT INTO admin_settings (key, value) VALUES 
      ('bkash_no', '01409084819'),
      ('nagad_no', '01409084819'),
      ('rocket_no', '01409084819'),
      ('max_bots_per_server', '4'),
      ('admin_password', '@1234567890@sojib@1234567890@sojib#')
      ON CONFLICT (key) DO NOTHING;
    `);

    lastDomainFetch = 0;
    await getActivePlatformDomains();

    const bots = await pool.query("SELECT id FROM whatsapp_bots WHERE status = 'CONNECTED'");
    for (const row of bots.rows) await startTenantBot(row.id);
  } catch (e) {
    console.error('[STARTUP INIT ERROR]:', e.message);
  }
});
