# Bastion usage counter

A tiny server that counts how many people run Bastion, **without knowing who they are**. It runs on Cloudflare's free plan, so there is nothing to host or pay for.

It stores only a random id per install (made on each PC) and the app version. It never reads or stores an IP address, and the app sends a ping **only** if the owner of that PC turns the option on (it is off by default).

## Set it up once
You need [Node.js](https://nodejs.org) and a free [Cloudflare](https://dash.cloudflare.com/sign-up) account.

```
npm install -g wrangler
wrangler login
cd server
wrangler kv namespace create USAGE      # paste the printed id into wrangler.toml
wrangler secret put ADMIN_TOKEN         # type a long random password; this is your private key
wrangler deploy                         # prints https://bastion-usage.<you>.workers.dev
```

Then:
1. Put that `https://...workers.dev` address into `bastion/telemetry.py` as `PING_URL`, and rebuild the app.
2. See your numbers any time by opening **`https://bastion-usage.<you>.workers.dev/stats?key=YOUR_ADMIN_TOKEN`** in a browser.

Only you have the token, so only you can see the counts. The token is never put in the app, so it cannot leak to users.

## What you see
Installs active in the last hour, 24 hours and 7 days, total installs seen in 30 days, and a breakdown by version. All anonymous.
