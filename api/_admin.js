const { verifyJwt, parseCookies } = require('./_jwt');

const ADMIN_IDS = new Set([
  '1328195818431451186',
  '1521369403399213186',
  '1545755252836409407',
]);

function getToken(req) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7);
  return parseCookies(req).ilegal_session || null;
}

function getUser(req) {
  return verifyJwt(getToken(req), process.env.SESSION_SECRET || 'fallback');
}

function isAdmin(user) {
  return Boolean(user && ADMIN_IDS.has(String(user.userId)));
}

function getSupabaseConfig() {
  const url = process.env.SUPABASE_URL || 'https://ofxrufnajnncstlrlswm.supabase.co';
  const key = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!key) throw new Error('SUPABASE_SECRET_KEY não configurada');
  return { url: url.replace(/\/$/, ''), key };
}

async function supabase(path, options = {}) {
  const { url, key } = getSupabaseConfig();
  const response = await fetch(`${url}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!response.ok) {
    const error = new Error(data?.message || data?.hint || `Supabase ${response.status}`);
    error.status = response.status;
    error.details = data;
    throw error;
  }
  return data;
}

function locationFromRequest(req) {
  return {
    country: String(req.headers['x-vercel-ip-country'] || '').slice(0, 80) || null,
    region: String(req.headers['x-vercel-ip-country-region'] || '').slice(0, 120) || null,
    city: String(req.headers['x-vercel-ip-city'] || '').slice(0, 120) || null,
  };
}

function ipFromRequest(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim().slice(0, 80);
  const real = req.headers['x-real-ip'];
  if (typeof real === 'string' && real.trim()) return real.trim().slice(0, 80);
  return req.socket?.remoteAddress || null;
}

module.exports = { ADMIN_IDS, getUser, isAdmin, supabase, locationFromRequest, ipFromRequest };
