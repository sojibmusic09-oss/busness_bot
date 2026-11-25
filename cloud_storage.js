/**
 * FreeSite SaaS — Cloud Storage Manager (Cloudinary Object Storage - Security Hardened)
 * Strict MIME whitelist (blocks SVG XSS), size limit, folder sanitization & WebP optimization.
 */

const cloudinary = require('cloudinary').v2;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'demo',
  api_key: process.env.CLOUDINARY_API_KEY || '',
  api_secret: process.env.CLOUDINARY_API_SECRET || '',
  secure: true
});

const ALLOWED_DATA_URI_REGEX = /^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+$/i;
const MAX_BASE64_LENGTH = 11 * 1024 * 1024; // ~8MB binary image

function isSafeRemoteImageUrl(urlStr) {
  try {
    const parsed = new URL(urlStr);
    if (!['https:', 'http:'].includes(parsed.protocol)) return false;
    const host = parsed.hostname.toLowerCase();
    if (['localhost', '127.0.0.1', '0.0.0.0', '::1', '169.254.169.254'].includes(host)) return false;
    if (host.startsWith('192.168.') || host.startsWith('10.') || host.endsWith('.local') || host.endsWith('.internal')) return false;
    return true;
  } catch (e) {
    return false;
  }
}

function sanitizeFolderPath(folder) {
  const cleaned = String(folder || 'freesite_products')
    .replace(/\.\./g, '')
    .replace(/[^a-zA-Z0-9/_-]/g, '')
    .replace(/^\/+|\/+$/g, '');
  return cleaned || 'freesite_products';
}

/**
 * Upload safe raster Base64 Data URI or public HTTPS Image URL to Cloudinary
 */
async function uploadProductImage(fileDataUri, folder = 'freesite_products') {
  if (!fileDataUri || typeof fileDataUri !== 'string') {
    throw new Error('No image payload provided');
  }

  const trimmed = fileDataUri.trim();

  if (trimmed.startsWith('data:')) {
    if (!ALLOWED_DATA_URI_REGEX.test(trimmed)) {
      throw new Error('Invalid image format. Only PNG, JPG, JPEG, WEBP, or GIF base64 images are allowed.');
    }
    if (trimmed.length > MAX_BASE64_LENGTH) {
      throw new Error('Image size exceeds the maximum allowed limit (8MB).');
    }
  } else if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    if (!isSafeRemoteImageUrl(trimmed)) {
      throw new Error('Unsafe or disallowed remote image URL.');
    }
  } else {
    throw new Error('Unsupported image payload format.');
  }

  if (!process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
    throw new Error('Cloud storage credentials are not configured on the server.');
  }

  const safeFolder = sanitizeFolderPath(folder);

  const result = await cloudinary.uploader.upload(trimmed, {
    folder: safeFolder,
    resource_type: 'image',
    allowed_formats: ['png', 'jpg', 'jpeg', 'webp', 'gif'],
    format: 'webp',
    transformation: [
      { quality: 'auto:good' },
      { fetch_format: 'auto' }
    ]
  });

  const thumbnailUrl = cloudinary.url(result.public_id, {
    width: 300,
    height: 300,
    crop: 'fill',
    quality: 'auto',
    format: 'webp'
  });

  return {
    imageUrl: result.secure_url,
    thumbnailUrl,
    publicId: result.public_id,
    width: result.width,
    height: result.height,
    format: result.format
  };
}

/**
 * Delete image from Cloudinary permanently
 */
async function deleteCloudImage(publicId) {
  if (!publicId || typeof publicId !== 'string') return false;
  try {
    const res = await cloudinary.uploader.destroy(publicId.trim(), { resource_type: 'image' });
    return res.result === 'ok' || res.result === 'not found';
  } catch (err) {
    console.error('[STORAGE]: Failed to delete cloud image:', err.message);
    return false;
  }
}

module.exports = {
  uploadProductImage,
  deleteCloudImage
};
