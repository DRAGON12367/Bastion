// Bastion usage counter - a Cloudflare Worker you run. It counts installs; it never stores an IP or anything that identifies a person.
//
// It answers two things:
//   POST /ping        {"id":"<random>","version":"1.0.1"}   -> records that this id was seen just now. No IP is read or kept.
//   GET  /stats?key=  <your admin token>                    -> shows you the counts (total, active now, by version). Private to you.
//
// Set up (once), with Node and the Cloudflare CLI installed:
//   npm create cloudflare@latest        (or: npm i -g wrangler)
//   wrangler kv namespace create USAGE  then put the id it prints into wrangler.toml
//   wrangler secret put ADMIN_TOKEN     then type a long random password
//   wrangler deploy
// Put the deployed https://... address into bastion/telemetry.py PING_URL and rebuild. Open https://.../stats?key=YOURTOKEN to see the numbers.

const SEEN_TTL = 60 * 60 * 24 * 35;   // an install drops off the count 35 days after its last ping
const ID = /^[a-f0-9]{32}$/;          // exactly the random id the app makes; nothing else is stored

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/ping") {
      let body;
      try { body = await request.json(); } catch { return new Response("bad", { status: 400 }); }
      const id = String(body.id || "");
      let version = String(body.version || "?").slice(0, 20).replace(/[^0-9A-Za-z.\-]/g, "");
      if (!ID.test(id)) return new Response("bad id", { status: 400 });
      // Key is the random id and the time. The request's IP is deliberately never read or written.
      await env.USAGE.put("seen:" + id, Date.now() + "|" + version, { expirationTtl: SEEN_TTL });
      return new Response(null, { status: 204 });
    }

    if (request.method === "GET" && url.pathname === "/stats") {
      if (!env.ADMIN_TOKEN || url.searchParams.get("key") !== env.ADMIN_TOKEN)
        return new Response("Not found", { status: 404 });
      const now = Date.now();
      let total = 0, active1h = 0, active24h = 0, active7d = 0;
      const versions = {};
      let cursor;
      do {
        const list = await env.USAGE.list({ prefix: "seen:", cursor });
        for (const k of list.keys) {
          const v = await env.USAGE.get(k.name);
          if (!v) continue;
          const [t, ver] = v.split("|");
          const age = now - Number(t);
          total++;
          if (age < 3600e3) active1h++;
          if (age < 86400e3) active24h++;
          if (age < 7 * 86400e3) active7d++;
          versions[ver] = (versions[ver] || 0) + 1;
        }
        cursor = list.list_complete ? null : list.cursor;
      } while (cursor);

      const data = { total_30d: total, active_last_hour: active1h, active_last_24h: active24h, active_last_7d: active7d, versions, generated: new Date().toISOString() };
      if ((request.headers.get("accept") || "").includes("text/html")) {
        const rows = Object.entries(versions).sort().map(([v, n]) => `<tr><td>${v}</td><td>${n}</td></tr>`).join("");
        return new Response(`<!doctype html><meta charset=utf-8><title>Bastion usage</title>
<style>body{font:16px system-ui;background:#0b0f15;color:#e2e8f0;max-width:620px;margin:40px auto;padding:0 16px}
h1{color:#26d07c}.n{font-size:48px;font-weight:700}.g{color:#8b96a5}table{border-collapse:collapse;margin-top:18px}td{padding:4px 18px 4px 0}</style>
<h1>Bastion usage</h1>
<p class=n>${active1h.toLocaleString()} <span class=g style=font-size:18px>running in the last hour</span></p>
<p>${active24h.toLocaleString()} active in the last 24 h &middot; ${active7d.toLocaleString()} in 7 days &middot; ${total.toLocaleString()} installs seen in 30 days</p>
<table><tr><td class=g>Version</td><td class=g>Installs</td></tr>${rows}</table>
<p class=g style=margin-top:28px>Anonymous counts. No IP addresses, no identities. Updated ${data.generated}.</p>`,
          { headers: { "content-type": "text/html; charset=utf-8" } });
      }
      return Response.json(data);
    }

    return new Response("Bastion usage counter", { status: 404 });
  },
};
