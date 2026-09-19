const { makeJwt } = require("../_jwt");

function getClientIp(req) {
  const forwardedFor = req.headers["x-forwarded-for"];
  if (typeof forwardedFor === "string" && forwardedFor.trim()) {
    return forwardedFor.split(",")[0].trim();
  }

  const realIp = req.headers["x-real-ip"];
  if (typeof realIp === "string" && realIp.trim()) {
    return realIp.trim();
  }

  return req.socket?.remoteAddress || "desconhecido";
}

function getUserAvatarUrl(user) {
  if (user.avatar) {
    const extension = user.avatar.startsWith("a_") ? "gif" : "png";
    return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.${extension}?size=128`;
  }

  const defaultAvatarIndex = Number((BigInt(user.id) >> 22n) % 6n);
  return `https://cdn.discordapp.com/embed/avatars/${defaultAvatarIndex}.png`;
}

async function logVerification(req, user) {
  const webhookUrl = process.env.VERIFICATION_LOG_WEBHOOK;
  if (!webhookUrl) {
    console.warn("VERIFICATION_LOG_WEBHOOK não configurado.");
    return;
  }

  const username = user.global_name || user.username || "desconhecido";
  const payload = {
    embeds: [
      {
        title: "Verificação",
        thumbnail: { url: getUserAvatarUrl(user) },
        fields: [
          { name: "ID", value: String(user.id), inline: true },
          { name: "Usuário", value: String(username).slice(0, 1024), inline: true },
          { name: "IP", value: getClientIp(req).slice(0, 1024), inline: true },
          { name: "Horário", value: new Date().toISOString(), inline: true },
        ],
        color: 0x5865f2,
      },
    ],
    allowed_mentions: { parse: [] },
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const webhookRes = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    if (!webhookRes.ok) {
      console.error("Falha ao enviar o log de verificação:", webhookRes.status);
    }
  } catch (err) {
    console.error(
      "Falha ao enviar o log de verificação:",
      err?.name === "AbortError" ? "timeout" : err?.message || "erro desconhecido"
    );
  } finally {
    clearTimeout(timeout);
  }
}

async function registerMember(req, user) {
  const supabaseUrl = process.env.SUPABASE_URL || "https://ofxrufnajnncstlrlswm.supabase.co";
  const supabaseKey = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseKey) return;
  const headers = {
    apikey: supabaseKey,
    Authorization: "Bearer " + supabaseKey,
    "Content-Type": "application/json",
    Prefer: "resolution=merge-duplicates,return=minimal",
  };
  const location = {
    country: String(req.headers["x-vercel-ip-country"] || "").slice(0, 80) || null,
    region: String(req.headers["x-vercel-ip-country-region"] || "").slice(0, 120) || null,
    city: String(req.headers["x-vercel-ip-city"] || "").slice(0, 120) || null,
  };
  await fetch(supabaseUrl.replace(/\/$/, "") + "/rest/v1/members?on_conflict=user_id", {
    method: "POST",
    headers,
    body: JSON.stringify({
      user_id: String(user.id),
      username: String(user.global_name || user.username || "desconhecido").slice(0, 120),
      avatar: user.avatar || null,
      ip_address: getClientIp(req).slice(0, 80),
      ...location,
      last_seen_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    }),
  });
}

module.exports = async function handler(req, res) {
  const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
  const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
  const GUILD_ID = process.env.DISCORD_GUILD_ID;
  const ROLE_ID = process.env.DISCORD_ROLE_ID;
  const VIP_ROLE_ID = process.env.DISCORD_VIP_ROLE_ID || "1542665006917619732";
  const SECRET = process.env.SESSION_SECRET || "fallback";

  const publicSiteUrl = process.env.PUBLIC_SITE_URL || process.env.SITE_URL;
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  const proto = req.headers["x-forwarded-proto"] || "https";
  const base = (publicSiteUrl || (proto + "://" + host)).replace(/\/$/, "");

  function send(res, dest) {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Location", dest);
    res.status(302).end();
  }

  const language = req.query && req.query.state === "en" ? "en" : "pt";
  const pagePath = language === "en" ? "/english.html" : "/";

  const code = req.query.code;
  if (!code) {
    send(res, base + pagePath + "?error=missing_code");
    return;
  }

  try {
    const redirectUri = base + "/api/auth/callback";

    const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
      }),
    });
    if (!tokenRes.ok) {
      send(res, base + pagePath + "?error=auth_failed");
      return;
    }

    const { access_token } = await tokenRes.json();

    const userRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: "Bearer " + access_token },
    });
    if (!userRes.ok) {
      send(res, base + pagePath + "?error=auth_failed");
      return;
    }
    const user = await userRes.json();

    let hasAccess = false;
    let hasVipAccess = false;
    const memberRes = await fetch(
      "https://discord.com/api/users/@me/guilds/" + GUILD_ID + "/member",
      { headers: { Authorization: "Bearer " + access_token } }
    );
    if (memberRes.ok) {
      const member = await memberRes.json();
      const roles = Array.isArray(member.roles) ? member.roles : [];
      hasAccess = roles.includes(ROLE_ID);
      hasVipAccess = roles.includes(VIP_ROLE_ID);
    }

    if (!hasAccess) {
      send(res, base + pagePath + "?error=no_access");
      return;
    }

    try {
      await registerMember(req, user);
    } catch (memberError) {
      console.error("Falha ao registrar membro:", memberError.message);
    }
    await logVerification(req, user);

    const jwt = makeJwt(
      {
        userId: user.id,
        username: user.global_name || user.username,
        avatar: user.avatar || null,
        hasAccess,
        hasVipAccess,
      },
      SECRET
    );

    // Passa o JWT pelo hash da URL (não vai pro servidor, fica só no browser)
    send(res, base + pagePath + "#jwt=" + encodeURIComponent(jwt));
  } catch (err) {
    console.error("Auth callback error:", err);
    send(res, base + pagePath + "?error=auth_failed");
  }
};

module.exports.logVerification = logVerification;
module.exports.getClientIp = getClientIp;
