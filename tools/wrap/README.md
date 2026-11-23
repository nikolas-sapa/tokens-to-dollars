# tools/wrap — thin adapters

Wrap the atomic tools hunters already trust. Never reinvent scanning —
the value is the fleet's judgment, not another port scanner.

Planned adapters (stdin/stdout JSON in, JSON out):

| Target tool | Wraps for |
|---|---|
| `subfinder` / `amass` | passive subdomain enum → asset graph nodes |
| `httpx` / `dnsx` | alive-check + tech fingerprint → asset observations |
| `katana` | crawling → endpoint nodes |
| `nuclei` (+templates) | known-vuln matching → candidate findings |
| `ffuf` | dir/param/vhost fuzzing → surface rows |
| `trufflehog` | secret exposure → verified-credential findings |
| Burp MCP | proxied req/resp capture → evidence dirs |

Design rules: deterministic output parsing; scope passed through the RoE
manifest (a wrapper refuses to run against assets not in the manifest);
request budgets enforced at the wrapper level.
