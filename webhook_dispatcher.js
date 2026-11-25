/**
 * FreeSite SaaS — Universal Webhook Event Dispatcher (SSRF Hardened)
 * Secure event notifications with HMAC-SHA256 signature verification, SSRF guard & delivery tracking.
 */

const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
const axios = require('axios');
const { pool } = require('./database');

function isPrivateOrReservedIp(ip) {
  if (!ip) return true;
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 10) return true; // 10.0.0.0/8
    if (parts[0] === 127) return true; // 127.0.0.0/8
    if (parts[0] === 0) return true; // 0.0.0.0/8
    if (parts[0] === 169 && parts[1] === 254) return true; // Link-local / Cloud metadata
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12
    if (parts[0] === 192 && parts[1] === 168) return true; // 192.168.0.0/16
    if (parts[0] >= 224) return true; // Multicast & Reserved
    return false;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80')) {
      return true;
    }
    if (lower.startsWith('::ffff:')) {
      return isPrivateOrReservedIp(lower.replace('::ffff:', ''));
    }
    return false;
  }
  return true;
}

async function isSafeWebhookUrl(targetUrl) {
  try {
    const parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;

    const hostname = parsed.hostname.toLowerCase();
    if (['localhost', 'ip6-localhost'].includes(hostname) || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
      return false;
    }

    if (net.isIP(hostname)) {
      return !isPrivateOrReservedIp(hostname);
    }

    const resolved = await dns.lookup(hostname, { all: true });
    if (!resolved || resolved.length === 0) return false;
    for (const addr of resolved) {
      if (isPrivateOrReservedIp(addr.address)) return false;
    }
    return true;
  } catch (e) {
    return false;
  }
}

async function triggerWebhookEvent(eventName, payloadData) {
  setImmediate(async () => {
    try {
      const hooks = await pool.query(
        `SELECT id, target_url, secret, subscribed_events 
         FROM api_webhooks 
         WHERE is_active = TRUE AND $1 = ANY(subscribed_events)`,
        [eventName]
      );

      if (hooks.rows.length === 0) return;

      const eventPayload = {
        event: eventName,
        timestamp: new Date().toISOString(),
        data: payloadData
      };
      const payloadString = JSON.stringify(eventPayload);

      for (const hook of hooks.rows) {
        const safeTarget = await isSafeWebhookUrl(hook.target_url);
        if (!safeTarget) {
          await pool.query(
            `INSERT INTO webhook_delivery_logs (webhook_id, event_name, payload, response_code, response_body, success)
             VALUES ($1, $2, $3, $4, $5, FALSE)`,
            [hook.id, eventName, eventPayload, 403, 'Blocked unsafe/private webhook target URL']
          );
          continue;
        }

        const signature = crypto
          .createHmac('sha256', hook.secret)
          .update(payloadString)
          .digest('hex');

        let success = false;
        let responseCode = null;
        let responseBody = '';
        let attempts = 0;

        for (let attempt = 1; attempt <= 3; attempt++) {
          attempts = attempt;
          try {
            const res = await axios.post(hook.target_url, eventPayload, {
              headers: {
                'Content-Type': 'application/json',
                'X-FreeSite-Event': eventName,
                'X-FreeSite-Signature': signature,
                'User-Agent': 'FreeSite-Webhook-Engine/1.0'
              },
              timeout: 6000,
              maxRedirects: 0
            });
            responseCode = res.status;
            responseBody = (typeof res.data === 'string' ? res.data : JSON.stringify(res.data || '')).substring(0, 300);
            success = true;
            break;
          } catch (err) {
            responseCode = err.response?.status || 500;
            const rawBody = err.response?.data
              ? (typeof err.response.data === 'string' ? err.response.data : JSON.stringify(err.response.data))
              : err.message;
            responseBody = String(rawBody || '').substring(0, 300);
            await new Promise((r) => setTimeout(r, 1500 * attempt));
          }
        }

        await pool.query(
          `INSERT INTO webhook_delivery_logs (webhook_id, event_name, payload, response_code, response_body, success, attempt_count)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [hook.id, eventName, eventPayload, responseCode, responseBody, success, attempts]
        );
      }
    } catch (globalErr) {
      console.error('[WEBHOOK ERROR]:', globalErr.message);
    }
  });
}

module.exports = {
  triggerWebhookEvent
};
