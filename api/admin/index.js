const { getUser, isAdmin, supabase } = require('../_admin');

const ADMIN_ROLES = {
  '1545755252836409407': 'Dono',
  '1521369403399213186': 'Sub Dono',
  '1328195818431451186': 'Executivo',
};

function deny(res, code, error) { return res.status(code).json({ error }); }
function body(req) { return req.body && typeof req.body === 'object' ? req.body : {}; }

module.exports = async function handler(req, res) {
  const user = getUser(req);
  if (!isAdmin(user)) return deny(res, 403, 'Admin access required');
  res.setHeader('Cache-Control', 'no-store');
  try {
    if (req.method === 'GET') {
      const now = encodeURIComponent(new Date().toISOString());
      const members = await supabase('members?select=*&order=last_seen_at.desc');
      let announcements;
      try {
        announcements = await supabase(`announcements?is_active=eq.true&or=(expires_at.is.null,expires_at.gt.${now})&select=*&order=created_at.desc&limit=30`);
      } catch (announcementError) {
        // Compatibilidade com instalações em que a coluna expires_at ainda não foi criada.
        announcements = await supabase('announcements?is_active=eq.true&select=*&order=created_at.desc&limit=30');
      }
      return res.json({ members: members || [], announcements: announcements || [], admin: { id: user.userId, name: user.username } });
    }
    if (req.method !== 'POST') return deny(res, 405, 'Method not allowed');
    const input = body(req);
    const action = String(input.action || '');
    if (action === 'member_status') {
      const target = String(input.userId || '');
      const status = ['active', 'limited', 'banned'].includes(input.status) ? input.status : null;
      if (!target || !status) return deny(res, 400, 'Invalid member status');
      await supabase(`members?user_id=eq.${encodeURIComponent(target)}`, { method: 'PATCH', headers: { Prefer: 'return=minimal' }, body: JSON.stringify({ status, updated_at: new Date().toISOString() }) });
      await supabase('admin_actions', { method: 'POST', headers: { Prefer: 'return=minimal' }, body: JSON.stringify({ admin_user_id: String(user.userId), target_user_id: target, action: status === 'banned' ? 'ban' : status === 'limited' ? 'limit' : 'unban', details: {} }) });
      return res.json({ ok: true });
    }
    if (action === 'announcement') {
      const message = String(input.message || '').trim().slice(0, 2000);
      if (!message) return deny(res, 400, 'Message is required');
      const authorAvatarUrl = user.avatar ? `https://cdn.discordapp.com/avatars/${user.userId}/${user.avatar}.png?size=128` : `https://cdn.discordapp.com/embed/avatars/${parseInt(user.userId, 10) % 6}.png`;
      const rows = await supabase('announcements', { method: 'POST', headers: { Prefer: 'return=representation' }, body: JSON.stringify({ title: null, message, image_url: null, author_avatar_url: authorAvatarUrl, author_role: ADMIN_ROLES[String(user.userId)] || 'Administrador', author_user_id: String(user.userId), author_name: String(user.username || 'Administrador').slice(0, 120) }) });
      return res.json({ ok: true, announcement: rows?.[0] || null });
    }
    if (action === 'deactivate_announcement') {
      const id = Number(input.id);
      if (!Number.isInteger(id)) return deny(res, 400, 'Invalid announcement');
      await supabase(`announcements?id=eq.${id}`, { method: 'PATCH', headers: { Prefer: 'return=minimal' }, body: JSON.stringify({ is_active: false }) });
      return res.json({ ok: true });
    }
    return deny(res, 400, 'Unknown action');
  } catch (error) {
    console.error('admin api error:', error.message);
    return res.status(500).json({ error: 'Database unavailable', detail: error.details?.message || error.message || 'unknown database error' });
  }
};
