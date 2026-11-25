<div align="center">

# ⚡ FreeSite SaaS
**Multi-Tenant E-Commerce Store Builder, Custom Domain Router & WhatsApp AI Automation Platform**

Developed with ❤️ by **Sojib**

[![WhatsApp](https://img.shields.io/badge/WhatsApp-01409084819-25D366?style=for-the-badge&logo=whatsapp&logoColor=white)](https://wa.me/8801409084819)
[![TikTok](https://img.shields.io/badge/TikTok-@sojib..music-000000?style=for-the-badge&logo=tiktok&logoColor=white)](https://tiktok.com/@sojib..music)

</div>

---

## 🌟 Core Highlights

- **Frosted Glassmorphism SaaS UI:** Mobile-first Bangla + English interface (`Plus Jakarta Sans` + `Hind Siliguri`) with Emerald `#059669` palette and translucent glass components.
- **Main Admin Custom Domain Manager:** Super Admin can add unlimited domains from `/admin`. Every store created on an added domain automatically resolves at:
  - Storefront: `https://<added-domain>/<storeSlug>` (e.g., `https://mybrand.com/myshop`)
  - Product Detail: `https://<added-domain>/<storeSlug>/p/<id>`
  - Owner Dashboard: `https://<added-domain>/dash/<storeSlug>`
- **WhatsApp AI Automation:** Individual WhatsApp sessions stored safely in PostgreSQL, supporting text, voice transcription, and product image analysis with live order alerts.
- **Universal Product Cloud API (`/api/v1`):** Header-authenticated (`X-API-KEY` + `X-SECRET-KEY`) REST API with OpenAPI docs at `/api/v1/docs`.

---

## 🔐 Security Architecture

- All `/api/admin/*` endpoints protected with `checkAdminAuth`, timing-safe password verification (`crypto.timingSafeEqual`), and `HttpOnly` cookies.
- Rate limiting via `express-rate-limit` on `/api/`, `/api/admin/login`, and `/api/v1/`.
- Strict XSS escaping (`escapeHtml`) and URL sanitization across dynamic HTML views.
- SSRF protection on Webhooks (`webhook_dispatcher.js`) and Website Analyzer (`website_analyzer.js`) blocking localhost, cloud metadata, and private IP ranges.
- Strict raster image MIME whitelist (`png`, `jpg`, `jpeg`, `webp`, `gif` — blocking SVG XSS) in `cloud_storage.js`.

---

## 🌐 How to Add a Custom Domain (`/myshop`)

1. Point your domain's DNS (`A` record or `CNAME`) to your deployment server (e.g., Render).
2. Log in to `/admin` using your Master Admin Password.
3. Open **ডোমেইন ম্যানেজার (`/myshop`)**, enter your domain (e.g., `shopbd.xyz`), and click **ডোমেইন অ্যাড করুন**.
4. Users can now select `shopbd.xyz` on the landing page (`/`) and launch stores directly at `https://shopbd.xyz/myshop`.

---

## ⚙️ Environment Variables

```env
PORT=3000
DATABASE_URL=postgresql://user:password@host/dbname?sslmode=require
ADMIN_PASSWORD=your_strong_admin_password
GEMINI_API_KEY=your_gemini_api_key
GEMINI_API_KEYS=key1,key2
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_cloudinary_key
CLOUDINARY_API_SECRET=your_cloudinary_secret
IMGBB_API_KEY=your_imgbb_key

freesite-builder/
├── public/
│   ├── index.html            # Public Landing & One-Click Shop Builder
│   ├── admin.html            # Super Admin Command Console + Domain Manager
│   └── catalog_builder.html  # Digital Catalog & Multi-Demo Builder
├── server.js                 # Master Express Server, Domain Router & WhatsApp Engine
├── worker.js                 # Multi-Server Background WhatsApp Worker
├── database.js               # PostgreSQL Connection & Core Schema
├── product_cloud_db.js       # Cloud API & Platform Domain Tables
├── ai_engine.js              # Gemini AI & Voice/Smart Search Engine
├── website_analyzer.js       # AI Website Link Analyzer
├── api_v1_router.js          # Universal Product REST API v1
├── cloud_storage.js          # Hardened Cloudinary Storage Manager
├── webhook_dispatcher.js     # SSRF-Hardened Webhook Dispatcher
├── package.json
└── README.md


---

আপনার সব ফাইল রেডি! ডিপ্লয় করার আগে `.env`-এ আপনার **`ADMIN_PASSWORD`**, **`DATABASE_URL`**, এবং **`GEMINI_API_KEY`** সেট করে `npm start` দিয়ে রান করুন। কোনো বাগ বা নতুন ফিচার দরকার হলে জানাবেন!
