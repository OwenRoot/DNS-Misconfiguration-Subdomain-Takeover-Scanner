# DNS Misconfiguration & Subdomain Takeover Scanner

A serverless, browser-based scanner that performs live DNS lookups to find dangling CNAME records and subdomains pointing at takeover-prone third-party providers. Built to run on Netlify with no build step and no local environment.

**Developed by: OwenRoot**

---

## Disclaimer

**This tool is for authorized use only.** Use it solely on domains you own or have explicit, written permission to assess.

- Scanning domains without authorization may be illegal in your jurisdiction.
- The author (OwenRoot) provides this software "as is", without warranty of any kind, and **accepts no responsibility or liability for misuse**, damage, or any legal consequences arising from its use.
- You are solely responsible for ensuring your use complies with all applicable laws, regulations, and agreements.

By using this tool, you agree to these terms.

---

## Features

- **Live DNS recon:** asynchronous `dns.resolveCname()` checks against 34 common enterprise subdomains (blog, docs, support, status, shop, pages and more), followed by target resolution checks. No HTTP requests are sent to the scanned domain.
- **Automated threat triage:**

  | Severity | Meaning |
  |---|---|
  | INFORMATIONAL | No CNAME record |
  | LOW | CNAME points to a live vendor with no takeover fingerprint |
  | MEDIUM | Reserved for inconclusive findings |
  | HIGH | CNAME matches a known takeover-prone provider fingerprint, or points to an unresolvable external domain |
  | CRITICAL | Fingerprint match and the CNAME target no longer resolves (NXDOMAIN) |

- **Remediation guidance:** HIGH and CRITICAL findings include a risk explanation and a "Remediation & Defense Strategy" covering how to delete or reclaim the record.
- **Response integrity:** results are base64-encoded and signed with HMAC-SHA256 using an ephemeral salt generated in the browser. The client recomputes the signature and refuses to render results on a mismatch.

## Guardrails

1. **Rate limiting:** one request per source IP per 10 seconds (HTTP 429 with `Retry-After`). The limit is held in memory, so it applies per warm function instance.
2. **Input sanitization:** strict domain regex, blocked internal TLDs, and salt format validation. Invalid input is rejected.
3. **Anti-SSRF:** CNAME targets that are localhost, IP literals, single-label names, or internal/non-routable domains are dropped silently.

Responses also carry `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, and a restrictive CSP.

## Project structure

```
├── netlify.toml
├── index.html
└── netlify/functions/scan-takeover.js
```

## Deploy on Netlify

1. Push this folder to a GitHub repository (keep the `netlify/functions/` path).
2. In Netlify, choose **Add new site > Import an existing project** and select the repo.
3. Leave the build command empty. Publish directory is `.` (set in `netlify.toml`).
4. Deploy. The function is served at `/.netlify/functions/scan-takeover`.

You can also drag and drop the folder into Netlify's manual deploy.

## API

```
GET /.netlify/functions/scan-takeover?domain=example.com&salt=<16-64 alphanumeric chars>
```

Response:

```json
{
  "algorithm": "HMAC-SHA256",
  "encoding": "base64",
  "payload": "<base64 JSON: domain, scannedAt, checked, findings[]>",
  "signature": "<hex HMAC-SHA256 of payload keyed with salt>"
}
```

## Limitations

- The HMAC key is chosen by the client, so it detects corruption in transit but does not authenticate the server.
- A fingerprint match is a strong indicator, not proof. Confirm on the provider side before reporting or remediating.
- The subdomain list is a small common-name wordlist, not exhaustive discovery.
- In-memory rate limiting is best-effort on serverless infrastructure.

## License

Provided for educational and authorized security assessment purposes. See the disclaimer above.
