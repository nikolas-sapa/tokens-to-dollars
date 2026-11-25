# analytics-receiver — optional central counter for opt-in usage stats

The CLI's analytics are **off by default**. Users who opt in POST the
strict-allowlist event (`v, ts, cmd, dur_ms, install_id, os` — nothing
else) to whatever endpoint is configured. This worker is the reference
receiver: it re-validates the allowlist server-side, so even a broken or
malicious client cannot store anything beyond the six public fields.

## Deploy (one-time, ~10 minutes, free tier)

1. Create a Cloudflare account at dash.cloudflare.com (free).
2. Install wrangler: `npm install -g wrangler` then `wrangler login`.
3. In this directory:
   ```
   wrangler kv namespace create T2D_EVENTS
   ```
   Copy the printed `id` into `wrangler.toml` below.
4. Create `wrangler.toml` here:
   ```toml
   name = "t2d-analytics"
   main = "worker.js"
   compatibility_date = "2026-01-01"

   [[kv_namespaces]]
   binding = "T2D_EVENTS"
   id = "<paste the id from step 3>"

   [vars]
   STATS_TOKEN = "<pick a long random string>"
   ```
5. `wrangler deploy` — it prints your worker URL, e.g.
   `https://t2d-analytics.<your-subdomain>.workers.dev`
6. Verify:
   ```
   curl -X POST https://<worker-url>/ingest -H 'content-type: application/json' \
     -d '{"v":"0.1.5","ts":1795600000,"cmd":"run","dur_ms":12,"install_id":"test","os":"darwin"}'
   curl "https://<worker-url>/stats?token=<your-stats-token>"
   ```
7. Tell the CLI where to send events **only for users who opt in**. The
   endpoint becomes the default in a future release; users can always
   override or stay dark:
   ```
   t2d analytics on
   # then set analytics.endpoint in ~/.config/tokens-to-dollars/config.json
   ```

## What this receiver can never know

Program names, target names, tool arguments, paths, findings, env vars,
or anything about what a user is hunting — the CLI never sends them and
the worker drops any field outside the six allowed ones anyway. The
`install_id` is a random UUID generated per machine; it is not derivable
from the user. IP addresses are visible to Cloudflare at the edge as
with any HTTP service but are never stored by this worker.

## Cost

Cloudflare Workers free tier: 100k requests/day, KV free tier: 100k
reads/day, 1k writes/day. Opt-in analytics volume for a young OSS project
is orders of magnitude below that.
