/**
 * FreeSite SaaS — Hardened Background Worker Node
 * Runs assigned WhatsApp bots from Neon PostgreSQL database with full AI & Order Alert support
 * Architect: Sojib
 */

require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const pino = require('pino');
const { GoogleGenAI } = require('@google/genai');
const {
  searchSmartProducts,
  transcribeAudioWithGemini,
  callGeminiUltraFast,
  GEMINI_MODEL
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
const PORT = process.env.PORT || 3001;
const SERVER_ID = parseInt(process.env.SERVER_ID || 2, 10);

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

const FALLBACK_DB_URL =
  'postgresql://neondb_owner:npg_FSBH1iGPo2za@ep-late-haze-bivsg8k8-pooler.c-5.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require';

function getSafeConnectionString() {
  const rawUrl = (process.env.DATABASE_URL || FALLBACK_DB_URL).trim();
  if (!rawUrl) return '';
  try {
    const parsed = new URL(rawUrl);
    if (parsed.searchParams.has('channel_binding')) {
      parsed.searchParams.delete('channel_binding');
    }
    if (!parsed.searchParams.has('sslmode')) {
      parsed.searchParams.set('sslmode', 'require');
    }
    return parsed.toString();
  } catch (e) {
    return rawUrl;
  }
}

const pool = new Pool({
  connectionString: getSafeConnectionString(),
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', (err) => {
  console.error(`[WORKER #${SERVER_ID} DB ERROR]:`, err.message);
});

const activeSockets = new Map();
const workerChatHistories = new Map();

// PostgreSQL Session Store
async function usePostgresAuthState(botId) {
  const getSession = async (key) => {
    const res = await pool.query(
      'SELECT session_data FROM whatsapp_sessions WHERE bot_id = $1 AND session_key = $2',
      [botId, key]
    );
    if (res.rows.length > 0) return JSON.parse(res.rows[0].session_data, BufferJSON.reviver);
    return null;
  };

  const setSession = async (key, value) => {
    if (value === null || value === undefined) {
      await pool.query('DELETE FROM whatsapp_sessions WHERE bot_id = $1 AND session_key = $2', [botId, key]);
    } else {
      await pool.query(
        `INSERT INTO whatsapp_sessions (bot_id, session_key, session_data, updated_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (bot_id, session_key) DO UPDATE SET session_data = $3, updated_at = NOW()`,
        [botId, key, JSON.stringify(value, BufferJSON.replacer)]
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
          const d = {};
          for (const id of ids) {
            const v = await getSession(`${type}-${id}`);
            if (v) d[id] = v;
          }
          return d;
        },
        set: async (data) => {
          for (const cat in data) {
            for (const id in data[cat]) {
              await setSession(`${cat}-${id}`, data[cat][id]);
            }
          }
        }
      }
    },
    saveCreds: () => setSession('creds', creds)
  };
}

// AI Execution (Gemini Models 100% Untouched)
async function executeWorkerGemini(botRow, userPrompt, systemPrompt, imageBuffer = null, imageMime = 'image/jpeg') {
  const dailyLimit = botRow.rate_limit_daily || 300;
  if ((botRow.requests_today || 0) >= dailyLimit && botRow.plan !== 'premium') {
    return 'ভাইয়া, আজকের জন্য আমাদের স্বয়ংক্রিয় এআই সেবার ফ্রি লিমিট শেষ হয়ে গিয়েছে। আরও আনলিমিটেড সেবার জন্য অ্যাডমিনের সাথে যোগাযোগ করুন ❤️';
  }

  let reply = '';
  let usedTokens = 0;
  const safeInstruction = typeof systemPrompt === 'string' && systemPrompt.trim()
    ? systemPrompt.trim()
    : 'তুমি একজন অমায়িক ও পেশাদার কাস্টমার সহকারী।';

  const customKeys = (botRow.gemini_api_key || '')
    .split(',')
    .map(k => k.trim())
    .filter(k => k.length > 20);

  if (customKeys.length > 0) {
    for (let i = 0; i < customKeys.length; i++) {
      try {
        const client = new GoogleGenAI({ apiKey: customKeys[i] });
        const contents = [];
        if (imageBuffer) {
          contents.push({ inlineData: { data: imageBuffer.toString('base64'), mimeType: imageMime } });
        }
        contents.push(userPrompt);

        const response = await client.models.generateContent({
          model: GEMINI_MODEL || 'gemini-2.5-flash',
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
        console.warn(`[WORKER #${SERVER_ID}]: Key #${i + 1} failed:`, err.message);
      }
    }
  }

  if (!reply) {
    try {
      reply = await callGeminiUltraFast(userPrompt, safeInstruction, imageBuffer, imageMime);
      usedTokens = 45;
    } catch (err) {
      console.error(`[WORKER #${SERVER_ID}]: Fallback AI error:`, err.message);
    }
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

  return reply || 'দুঃখিত ভাইয়া, এই মুহূর্তে একটু ব্যস্ত আছি। অনুগ্রহ করে কিছুক্ষণ পর আবার চেষ্টা করুন।';
}

async function handleWorkerMessage(botRow, customerPhone, text, sock, imageBuffer = null, imageMime = null) {
  const cleanInput = (text || '').trim();
  const botId = botRow.id;
  const historyKey = `${botId}_${customerPhone}`;

  if (!workerChatHistories.has(historyKey)) workerChatHistories.set(historyKey, []);
  const history = workerChatHistories.get(historyKey);

  let catalogContext = '';
  const source = botRow.knowledge_source || (botRow.bot_type === 'business_site' ? 'website' : 'catalog');

  if (source === 'website' && botRow.website_url) {
    catalogContext = `আমাদের মূল ওয়েবসাইটের তথ্য ও লিংক: ${botRow.website_url}। বিবরণ: ${botRow.system_prompt || ''}`;
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

    const searchResult = searchSmartProducts(cleanInput, cachedCatalog);
    if (searchResult.items && searchResult.items.length > 0) {
      catalogContext = searchResult.items
        .map(p => `• [ID:${p.id}] ${p.name} | মূল্য: ৳${p.price} | ক্যাটাগরি: ${p.category} | লিংক: ${p.buy_link}`)
        .join('\n');
    }
  }

  const historyText = history.length > 0
    ? history.map(h => `${h.role === 'user' ? 'গ্রাহক' : 'অ্যাসিস্ট্যান্ট'}: ${h.text}`).join('\n')
    : 'এখনই কথোপকথন শুরু হয়েছে।';

  const systemPrompt = botRow.bot_type === 'personal'
    ? `তুমি ${botRow.bot_name} এর ব্যক্তিগত সহকারী। নির্দেশনা: ${botRow.system_prompt || ''}।\nইতিহাস:\n${historyText}`
    : `তুমি ${botRow.bot_name} এর একজন অমায়িক ও বিনয়ী সেলস/সাপোর্ট অ্যাসিস্ট্যান্ট।
বিবরণ: ${botRow.system_prompt || 'আমরা মানসম্মত পণ্য ও সেবা দিয়ে থাকি।'}
স্টক ডাটা:
${catalogContext || 'কোনো নির্দিষ্ট প্রোডাক্ট খোঁজা হয়নি।'}
ডেলিভারি চার্জ (শুধু অর্ডারের সময় বলবে): সিটির ভেতরে ৳${botRow.delivery_inside || 70}, বাইরে ৳${botRow.delivery_outside || 130}।
ইতিহাস:
${historyText}`;

  const userPrompt = imageBuffer
    ? `[ছবি বিশ্লেষণ]: গ্রাহক এই ছবিটি পাঠিয়ে লিখেছেন: "${cleanInput || 'এই পণ্যটি কি আপনাদের কাছে আছে?'}"`
    : `গ্রাহক: "${cleanInput}"`;

  let reply = await executeWorkerGemini(botRow, userPrompt, systemPrompt, imageBuffer, imageMime);
  reply = reply.replace(/\*\*/g, '*');

  const lowerText = cleanInput.toLowerCase();
  const isOrderIntent = lowerText.includes('order') || lowerText.includes('অর্ডার') || lowerText.includes('নিতে চাই') || lowerText.includes('কনফার্ম') || lowerText.includes('ঠিকানা');
  const hasPhone = /01[3-9]\d{8}/.test(cleanInput);

  if ((isOrderIntent || hasPhone) && sock) {
    try {
      const ownerAlertNumber = botRow.alert_phone || botRow.phone_number;
      if (ownerAlertNumber) {
        let cleanOwnerPhone = String(ownerAlertNumber).replace(/[^0-9]/g, '');
        if (cleanOwnerPhone.startsWith('01') && cleanOwnerPhone.length === 11) cleanOwnerPhone = '88' + cleanOwnerPhone;
        const ownerJid = `${cleanOwnerPhone}@s.whatsapp.net`;

        const alertMsg = `🚨 *নতুন অর্ডার অ্যালার্ট!* 🛍️\n` +
          `👤 *দোকান:* ${botRow.bot_name}\n` +
          `📞 *কাস্টমার:* +${customerPhone}\n` +
          `💬 *মেসেজ:* ${cleanInput}\n` +
          `👉 wa.me/${customerPhone}`;

        await sock.sendMessage(ownerJid, { text: alertMsg });
        await pool.query(
          `INSERT INTO bot_orders (bot_id, customer_phone, product_details) VALUES ($1, $2, $3)`,
          [botId, customerPhone, cleanInput]
        );
      }
    } catch (e) {}
  }

  history.push({ role: 'user', text: cleanInput || 'ছবি পাঠিয়েছেন', time: Date.now() });
  history.push({ role: 'assistant', text: reply, time: Date.now() });
  if (history.length > 8) history.shift();

  return reply;
}

async function startWorkerBot(botId) {
  try {
    const res = await pool.query('SELECT * FROM whatsapp_bots WHERE id = $1', [botId]);
    if (res.rows.length === 0) return;
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
      connectTimeoutMs: 60000,
      keepAliveIntervalMs: 25000,
      defaultQueryTimeoutMs: 60000
    });

    activeSockets.set(botId, sock);
    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', async (u) => {
      if (u.connection === 'open') {
        console.log(`[WORKER #${SERVER_ID}]: ✅ Bot #${botId} Connected!`);
        await pool.query("UPDATE whatsapp_bots SET status = 'CONNECTED' WHERE id = $1", [botId]);
      } else if (u.connection === 'close') {
        activeSockets.delete(botId);
        await pool.query("UPDATE whatsapp_bots SET status = 'DISCONNECTED' WHERE id = $1", [botId]);
        const shouldReconnect = u.lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
        if (shouldReconnect) {
          setTimeout(() => startWorkerBot(botId), 10000);
        } else {
          console.log(`[WORKER #${SERVER_ID}]: Bot #${botId} logged out. Waiting for new pairing.`);
        }
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
          } catch (e) {}
        }

        if (isAudio) {
          try {
            const buffer = await downloadMediaMessage(msg, 'buffer', {}, { logger: pino({ level: 'silent' }) });
            text = await transcribeAudioWithGemini(buffer, msgContent.audioMessage.mimetype || 'audio/ogg');
          } catch (e) {}
        }

        if (!text && !isImage) return;

        const latestRes = await pool.query('SELECT * FROM whatsapp_bots WHERE id = $1', [botId]);
        const latestBot = latestRes.rows[0] || botRow;

        let reply = await handleWorkerMessage(latestBot, cleanSender, text, sock, imageBuffer, imageMime);
        if (isAudio) reply = `🎤 *ভয়েস রেকর্ড:* "${text}"\n\n${reply}`;

        const typingDelay = Math.min(2500, Math.max(1000, reply.length * 15));
        await delay(typingDelay);

        await sock.sendMessage(sender, { text: reply });
        await sock.sendPresenceUpdate('paused', sender);
      } catch (err) {
        console.error(`[WORKER #${SERVER_ID} MSG ERROR]:`, err.message);
      }
    });
  } catch (e) {
    console.error(`Bot #${botId} worker error:`, e.message);
  }
}

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    workerId: SERVER_ID,
    runningBots: activeSockets.size,
    uptime: Math.floor(process.uptime())
  });
});

app.listen(PORT, '0.0.0.0', async () => {
  console.log(`[INFO]: Worker #${SERVER_ID} listening on port ${PORT}`);
  try {
    const bots = await pool.query("SELECT id FROM whatsapp_bots WHERE server_id = $1 AND status = 'CONNECTED'", [SERVER_ID]);
    for (const b of bots.rows) {
      await delay(500);
      await startWorkerBot(b.id);
    }
  } catch (err) {
    console.error(`[WORKER #${SERVER_ID} INIT ERROR]:`, err.message);
  }
});
