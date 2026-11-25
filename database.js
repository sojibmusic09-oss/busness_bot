/**
 * FreeSite Builder & WhatsApp Bot SaaS — Database Engine
 * Automatic Schema Initialization, Safe Neon Pooler Connection & Optional Neon Data API Client
 */

const { Pool } = require('pg');
const axios = require('axios');

const FALLBACK_DB_URL =
  'postgresql://neondb_owner:npg_FSBH1iGPo2za@ep-late-haze-bivsg8k8-pooler.c-5.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require';

/**
 * Neon Pooled URL থেকে channel_binding প্যারামিটার নিরাপদভাবে হ্যান্ডেল করে
 * যাতে pg@^8.13.1 ড্রাইভারে SSL কানেকশন এরর না হয়
 */
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

const connectionString = getSafeConnectionString();

// Neon.tech ডাটাবেজ পুল কানেকশন
const pool = new Pool({
  connectionString,
  ssl: {
    rejectUnauthorized: false
  },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('connect', () => {
  console.log('[INFO]: ✅ Neon PostgreSQL Database Connected Successfully!');
});

pool.on('error', (err) => {
  console.error('[ERROR]: Database Pool Error:', err.message);
});

/**
 * Optional Helper: Neon Data API (/rest/v1) এর মাধ্যমে HTTPS রিকোয়েস্ট পাঠানোর জন্য
 */
async function neonDataApiRequest(tableName, { method = 'GET', jwt = '', query = '', body = null } = {}) {
  const baseUrl = (
    process.env.NEON_DATA_API_URL ||
    'https://ep-late-haze-bivsg8k8.apirest.c-5.ap-southeast-1.aws.neon.tech/neondb/rest/v1'
  ).replace(/\/+$/, '');

  const safeTable = String(tableName || '').replace(/[^a-zA-Z0-9_]/g, '');
  const url = `${baseUrl}/${safeTable}${query ? `?${query}` : ''}`;

  const headers = { 'Content-Type': 'application/json' };
  if (jwt) headers.Authorization = `Bearer ${jwt}`;

  const response = await axios({
    method,
    url,
    headers,
    data: body || undefined,
    timeout: 8000
  });
  return response.data;
}

/**
 * সার্ভার চালু হলে সব টেবিল স্বয়ংক্রিয়ভাবে তৈরি হবে
 */
async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // ১. ইউজার টেবিল
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        plan VARCHAR(50) DEFAULT 'free',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // ২. সার্ভার ম্যানেজমেন্ট টেবিল
    await client.query(`
      CREATE TABLE IF NOT EXISTS worker_servers (
        id SERIAL PRIMARY KEY,
        server_name VARCHAR(100) NOT NULL,
        server_url VARCHAR(255) UNIQUE NOT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        max_capacity INT DEFAULT 10,
        current_load INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // ৩. হোয়াটসঅ্যাপ বট টেবিল
    await client.query(`
      CREATE TABLE IF NOT EXISTS whatsapp_bots (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        server_id INT REFERENCES worker_servers(id) ON DELETE SET NULL,
        bot_name VARCHAR(100) NOT NULL,
        phone_number VARCHAR(30),
        website_url VARCHAR(255),
        system_prompt TEXT,
        addressing_style VARCHAR(50) DEFAULT 'ভাইয়া',
        delivery_inside INT DEFAULT 70,
        delivery_outside INT DEFAULT 130,
        admin_phone VARCHAR(30),
        telegram_token VARCHAR(255),
        telegram_chat_id VARCHAR(100),
        status VARCHAR(50) DEFAULT 'DISCONNECTED',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // ৪. হোয়াটসঅ্যাপ সেশন টেবিল
    await client.query(`
      CREATE TABLE IF NOT EXISTS whatsapp_sessions (
        bot_id INT NOT NULL,
        session_key VARCHAR(255) NOT NULL,
        session_data TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (bot_id, session_key)
      );
    `);

    // ৫. ওয়েবসাইট পণ্য ক্যাটালগ টেবিল
    await client.query(`
      CREATE TABLE IF NOT EXISTS bot_products (
        id SERIAL PRIMARY KEY,
        bot_id INT REFERENCES whatsapp_bots(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        price NUMERIC(10, 2) DEFAULT 0,
        category VARCHAR(100),
        in_stock BOOLEAN DEFAULT TRUE,
        buy_link TEXT,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // ৬. ওয়েবসাইট হোস্ট ও সাবডোমেইন টেবিল
    await client.query(`
      CREATE TABLE IF NOT EXISTS hosted_websites (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        subdomain VARCHAR(100) NOT NULL,
        base_domain VARCHAR(100) NOT NULL,
        html_content TEXT,
        is_published BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (subdomain, base_domain)
      );
    `);

    // ৭. মেইন অ্যাডমিন কাস্টম ডোমেইন টেবিল (/myshop রাউটিং)
    await client.query(`
      CREATE TABLE IF NOT EXISTS platform_domains (
        id SERIAL PRIMARY KEY,
        domain_name VARCHAR(255) UNIQUE NOT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query('COMMIT');
    console.log('[INFO]: ✅ All SaaS Database Tables Initialized Automatically!');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[ERROR]: Failed to initialize database tables:', err.message);
  } finally {
    client.release();
  }
}

module.exports = {
  pool,
  initializeDatabase,
  neonDataApiRequest
};
