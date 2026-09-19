module.exports = function handler(req, res) {
    const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
    if (!CLIENT_ID) {
      res.status(500).send("Missing DISCORD_CLIENT_ID");
      return;
    }

    const publicSiteUrl = process.env.PUBLIC_SITE_URL || process.env.SITE_URL;
    const host = req.headers["x-forwarded-host"] || req.headers.host;
    const proto = req.headers["x-forwarded-proto"] || "https";
    const baseUrl = (publicSiteUrl || (proto + "://" + host)).replace(/\/$/, "");
    const redirectUri = baseUrl + "/api/auth/callback";
    const language = req.query && req.query.state === "en" ? "en" : "pt";

    const params = new URLSearchParams({
      client_id:     CLIENT_ID,
      redirect_uri:  redirectUri,
      response_type: "code",
      scope:         "identify guilds.members.read",
      prompt:        "consent",
      state:         language,
    });

    res.redirect("https://discord.com/oauth2/authorize?" + params.toString());
  };
