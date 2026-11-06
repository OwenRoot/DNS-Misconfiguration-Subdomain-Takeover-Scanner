'use strict';

/**
 * scan-takeover.js
 * Passive DNS misconfiguration / subdomain takeover scanner.
 * Only performs public DNS lookups (CNAME, A, AAAA). No HTTP requests are
 * made to the target. Use only on domains you own or are authorised to test.
 */

const dns = require('dns');
const net = require('net');
const crypto = require('crypto');

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

const RATE_WINDOW_MS = 10_000;
const rateCache = new Map(); // ip -> last accepted request timestamp (per warm instance)

const resolver = new dns.promises.Resolver({ timeout: 2500, tries: 2 });

const SUBDOMAINS = [
  'blog', 'docs', 'support', 'status', 'shop', 'pages', 'help', 'careers',
  'jobs', 'dev', 'staging', 'test', 'beta', 'app', 'portal', 'wiki', 'learn',
  'community', 'store', 'cdn', 'assets', 'static', 'media', 'news', 'info',
  'go', 'forum', 'api', 'www', 'mail', 'email', 'events', 'press', 'partners'
];

// Domain: labels of 1-63 chars, no leading/trailing hyphen, alphabetic TLD, <=253 total.
const DOMAIN_RE = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const SALT_RE = /^[A-Za-z0-9]{16,64}$/;
const BLOCKED_TLDS = new Set([
  'local', 'localhost', 'internal', 'intranet', 'lan', 'home', 'corp',
  'localdomain', 'test', 'invalid', 'example', 'arpa'
]);

const SEVERITY_RANK = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFORMATIONAL: 1 };

/* Known takeover-prone provider fingerprints (CNAME suffix patterns). */
const FINGERPRINTS = [
  {
    provider: 'GitHub Pages', re: /\.github\.io$/,
    claim: 'Re-create the GitHub repository / Pages site and add the custom domain under Settings > Pages (and verify the domain at the GitHub organisation level).'
  },
  {
    provider: 'Amazon S3 Website', re: /(?:^|\.)s3[.-](?:website[.-])?[a-z0-9-]*\.?amazonaws\.com$|\.s3\.amazonaws\.com$/,
    claim: 'Re-create the S3 bucket with the exact same name in the same region, or remove the DNS record.'
  },
  {
    provider: 'AWS Elastic Beanstalk', re: /\.elasticbeanstalk\.com$/,
    claim: 'Re-create the Elastic Beanstalk environment with the same CNAME prefix, or remove the DNS record.'
  },
  {
    provider: 'Heroku', re: /\.(?:herokuapp|herokudns|herokussl)\.com$/,
    claim: 'Re-create the Heroku app and attach the custom domain, or remove the DNS record.'
  },
  {
    provider: 'Zendesk', re: /\.zendesk\.com$/,
    claim: 'Re-activate the Zendesk subdomain (Admin > Account > Branding > host mapping) or remove the DNS record.'
  },
  {
    provider: 'Microsoft Azure App Service', re: /\.azurewebsites\.net$/,
    claim: 'Re-create the App Service with the same name and bind the custom domain, or remove the DNS record.'
  },
  {
    provider: 'Microsoft Azure Traffic Manager', re: /\.trafficmanager\.net$/,
    claim: 'Re-create the Traffic Manager profile with the same DNS name, or remove the DNS record.'
  },
  {
    provider: 'Microsoft Azure Cloud Service / VM', re: /\.(?:cloudapp\.net|cloudapp\.azure\.com)$/,
    claim: 'Re-allocate the public IP / cloud service DNS label, or remove the DNS record.'
  },
  {
    provider: 'Microsoft Azure Blob Storage', re: /\.blob\.core\.windows\.net$/,
    claim: 'Re-create the storage account with the same name, or remove the DNS record.'
  },
  {
    provider: 'Shopify', re: /\.myshopify\.com$/,
    claim: 'Reconnect the domain under Shopify > Settings > Domains, or remove the DNS record.'
  },
  {
    provider: 'Atlassian Statuspage', re: /\.stspg-customer\.com$/,
    claim: 'Re-create the status page and re-add the custom domain, or remove the DNS record.'
  },
  {
    provider: 'Fastly', re: /\.fastly\.net$/,
    claim: 'Add the domain back to a Fastly service you control, or remove the DNS record.'
  },
  {
    provider: 'Pantheon', re: /\.pantheonsite\.io$/,
    claim: 'Re-add the custom domain to the Pantheon environment, or remove the DNS record.'
  },
  {
    provider: 'Ghost(Pro)', re: /\.ghost\.io$/,
    claim: 'Re-create the Ghost site and custom domain mapping, or remove the DNS record.'
  },
  {
    provider: 'Surge.sh', re: /\.surge\.sh$/,
    claim: 'Re-deploy a project to the same surge domain, or remove the DNS record.'
  },
  {
    provider: 'Bitbucket Cloud', re: /\.bitbucket\.io$/,
    claim: 'Re-create the Bitbucket repository for the site, or remove the DNS record.'
  },
  {
    provider: 'Readme.io', re: /\.readme\.io$/,
    claim: 'Re-create the project and custom domain mapping, or remove the DNS record.'
  },
  {
    provider: 'HelpScout Docs', re: /\.helpscoutdocs\.com$/,
    claim: 'Re-create the Docs site and custom domain, or remove the DNS record.'
  },
  {
    provider: 'Unbounce', re: /\.unbouncepages\.com$/,
    claim: 'Re-add the domain in the Unbounce account, or remove the DNS record.'
  },
  {
    provider: 'Freshdesk', re: /\.freshdesk\.com$/,
    claim: 'Re-activate the helpdesk with the same vanity URL, or remove the DNS record.'
  },
  {
    provider: 'Tumblr', re: /\.tumblr\.com$/,
    claim: 'Re-claim the blog and custom domain mapping, or remove the DNS record.'
  }
];

/* Well-known managed vendors that are not takeover-prone on their own. */
const KNOWN_VENDORS = [
  [/\.cloudfront\.net$/, 'Amazon CloudFront'],
  [/\.cloudflare\.net$|\.cdn\.cloudflare\.net$/, 'Cloudflare'],
  [/\.akamaiedge\.net$|\.akamai\.net$|\.edgekey\.net$|\.edgesuite\.net$/, 'Akamai'],
  [/\.azurefd\.net$/, 'Azure Front Door'],
  [/\.googleusercontent\.com$|\.ghs\.googlehosted\.com$|^ghs\.google\.com$/, 'Google'],
  [/\.netlify\.app$|\.netlify\.com$/, 'Netlify'],
  [/\.vercel-dns\.com$|\.vercel\.app$/, 'Vercel'],
  [/\.wpengine\.com$/, 'WP Engine'],
  [/\.outlook\.com$|\.office365\.com$/, 'Microsoft 365']
];

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

const BASE_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'"
};

function respond(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: { ...BASE_HEADERS, ...extraHeaders },
    body: JSON.stringify(body)
  };
}

function clientIp(event) {
  const h = event.headers || {};
  return (
    h['x-nf-client-connection-ip'] ||
    (h['x-forwarded-for'] || '').split(',')[0].trim() ||
    h['client-ip'] ||
    'unknown'
  );
}

function pruneRateCache(now) {
  for (const [ip, ts] of rateCache) {
    if (now - ts > RATE_WINDOW_MS * 6) rateCache.delete(ip);
  }
}

/** Guardrail 3: anti-SSRF / internal-target filter. Returns true if unsafe. */
function isInternalTarget(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h || h.length > 253) return true;
  if (net.isIP(h)) return true; // CNAMEs must be hostnames, never IP literals
  if (!h.includes('.')) return true; // single-label / bare hostnames
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  const tld = h.split('.').pop();
  if (BLOCKED_TLDS.has(tld)) return true;
  if (/^(?:\d{1,3}\.){3}\d{1,3}(?:\.|$)/.test(h)) return true; // numeric-looking host
  if (/(?:^|\.)(?:metadata\.google\.internal|instance-data)$/.test(h)) return true;
  return !DOMAIN_RE.test(h);
}

function signPayload(payloadB64, salt) {
  return crypto.createHmac('sha256', salt).update(payloadB64, 'utf8').digest('hex');
}

/** Returns 'resolves' | 'nxdomain' | 'unknown' for a CNAME target. */
async function targetState(target) {
  const outcomes = await Promise.allSettled([
    resolver.resolve4(target),
    resolver.resolve6(target)
  ]);
  if (outcomes.some((o) => o.status === 'fulfilled' && o.value.length)) return 'resolves';
  const codes = outcomes.map((o) => (o.status === 'rejected' ? o.reason && o.reason.code : null));
  if (codes.every((c) => c === 'ENOTFOUND')) return 'nxdomain';
  if (codes.some((c) => c === 'ENODATA' || c === 'ENOTFOUND') && !codes.some((c) => c === 'ETIMEOUT' || c === 'ESERVFAIL' || c === 'ECONNREFUSED')) {
    return 'resolves'; // name exists but only has the other address family
  }
  return 'unknown';
}

function buildRemediation(fqdn, cname, fp, nxdomain) {
  const reclaim = fp
    ? `Option B - Reclaim: ${fp.claim}`
    : 'Option B - Reclaim: re-register the expired domain (or re-create the resource) so it is owned by your organisation again.';
  return [
    `Remediation & Defense Strategy for ${fqdn}:`,
    `1) Triage now: confirm in your DNS zone that the CNAME ${fqdn} -> ${cname} is still required. Check with the service owner before changing anything.`,
    `2) Option A - Delete (preferred when unused): remove the CNAME record for "${fqdn}" at your authoritative DNS provider (for example: Route 53 / Azure DNS / Cloudflare / BIND zone file) and let the TTL expire. Dangling-record exposure ends once resolvers drop the cached record.`,
    `3) ${reclaim}`,
    nxdomain
      ? '4) The CNAME target does not resolve at all (NXDOMAIN). Treat this as active exposure: anyone who can register or claim that name can serve content on your subdomain.'
      : '4) The target resolves, so verify ownership of the resource on the provider side (the provider may still return an unclaimed-resource page).',
    '5) Hardening: delete DNS records before decommissioning cloud resources, keep a CNAME inventory, use provider domain-verification (TXT) features, avoid wildcard cookies/CORS on the parent domain, and run this scan on a schedule.'
  ].join('\n');
}

/* ------------------------------------------------------------------ */
/* Triage                                                              */
/* ------------------------------------------------------------------ */

async function inspectSubdomain(sub, root) {
  const fqdn = `${sub}.${root}`;
  const scannedAt = new Date().toISOString();
  let records;

  try {
    records = await resolver.resolveCname(fqdn);
  } catch (err) {
    const code = (err && err.code) || 'UNKNOWN';
    const detail =
      code === 'ENODATA'
        ? 'Subdomain exists but has no CNAME record (A/AAAA/other record types only).'
        : code === 'ENOTFOUND'
        ? 'No DNS records found for this subdomain (NXDOMAIN).'
        : `DNS lookup did not complete (${code}).`;
    return {
      subdomain: fqdn, cname: null, severity: 'INFORMATIONAL',
      provider: null, status: 'NO_CNAME', description: detail,
      remediation: null, scannedAt
    };
  }

  // Guardrail 3: drop internal / non-routable targets silently.
  const safe = (records || [])
    .map((r) => String(r).toLowerCase().replace(/\.$/, ''))
    .filter((r) => !isInternalTarget(r));
  if (!safe.length) return null;

  const cname = safe[0];
  const fp = FINGERPRINTS.find((f) => f.re.test(cname));
  const state = await targetState(cname);

  if (fp) {
    const critical = state === 'nxdomain';
    return {
      subdomain: fqdn, cname,
      severity: critical ? 'CRITICAL' : 'HIGH',
      provider: fp.provider,
      status: critical ? 'DANGLING_NXDOMAIN' : 'FINGERPRINT_MATCH',
      description: critical
        ? `${fqdn} is aliased to ${cname}, a ${fp.provider} endpoint that no longer resolves. The provider name can potentially be claimed by an attacker, allowing them to host content on your trusted subdomain (phishing, cookie theft, malware delivery, brand abuse).`
        : `${fqdn} is aliased to ${cname}, a ${fp.provider} endpoint. ${fp.provider} is a provider commonly associated with subdomain takeover when the underlying resource is deleted or unclaimed. The target still resolves, so this is a high-risk indicator that must be verified on the provider side (look for an "unclaimed" / "not found" provider page).`,
      remediation: buildRemediation(fqdn, cname, fp, critical),
      scannedAt
    };
  }

  if (state === 'nxdomain') {
    return {
      subdomain: fqdn, cname,
      severity: 'HIGH',
      provider: 'Unresolvable external domain',
      status: 'DANGLING_NXDOMAIN',
      description: `${fqdn} is aliased to ${cname}, which does not resolve. If that domain has expired or is unregistered, an attacker could register it and control what ${fqdn} serves.`,
      remediation: buildRemediation(fqdn, cname, null, true),
      scannedAt
    };
  }

  const vendor = KNOWN_VENDORS.find(([re]) => re.test(cname));
  return {
    subdomain: fqdn, cname,
    severity: 'LOW',
    provider: vendor ? vendor[1] : 'Third-party service',
    status: state === 'resolves' ? 'LIVE' : 'LIVE_UNVERIFIED',
    description: state === 'resolves'
      ? `CNAME points to a live ${vendor ? vendor[1] : 'third-party'} endpoint (${cname}). No known takeover fingerprint matched.`
      : `CNAME points to ${cname}; target resolution was inconclusive. No known takeover fingerprint matched.`,
    remediation: null,
    scannedAt
  };
}

/* ------------------------------------------------------------------ */
/* Handler                                                             */
/* ------------------------------------------------------------------ */

exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') {
    return respond(405, { error: 'Method not allowed. Use GET.' }, { Allow: 'GET' });
  }

  // Guardrail 1: rate limiting (one query per source IP per 10 s).
  const now = Date.now();
  const ip = clientIp(event);
  pruneRateCache(now);
  const last = rateCache.get(ip);
  if (last && now - last < RATE_WINDOW_MS) {
    const retry = Math.ceil((RATE_WINDOW_MS - (now - last)) / 1000);
    return respond(
      429,
      { error: `Rate limit exceeded. Retry in ${retry}s.`, retryAfter: retry },
      { 'Retry-After': String(retry) }
    );
  }
  rateCache.set(ip, now);

  // Guardrail 2: input sanitisation.
  const qs = event.queryStringParameters || {};
  const rawDomain = typeof qs.domain === 'string' ? qs.domain.trim().toLowerCase().replace(/\.$/, '') : '';
  const salt = typeof qs.salt === 'string' ? qs.salt : '';

  if (!SALT_RE.test(salt)) {
    return respond(400, { error: 'Invalid handshake salt. Expected 16-64 alphanumeric characters.' });
  }
  if (!DOMAIN_RE.test(rawDomain) || BLOCKED_TLDS.has(rawDomain.split('.').pop())) {
    return respond(400, { error: 'Invalid domain. Provide a public root domain such as example.com.' });
  }
  if (isInternalTarget(rawDomain)) {
    return respond(400, { error: 'Target rejected: internal or non-routable names are not allowed.' });
  }

  try {
    // Skip the scan entirely if the root domain does not exist at all.
    const settled = await Promise.all(SUBDOMAINS.map((s) => inspectSubdomain(s, rawDomain).catch(() => null)));
    const findings = settled
      .filter(Boolean)
      .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.subdomain.localeCompare(b.subdomain));

    const payloadObj = {
      domain: rawDomain,
      scannedAt: new Date().toISOString(),
      checked: SUBDOMAINS.length,
      findings
    };
    const payload = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64');
    const signature = signPayload(payload, salt);

    return respond(200, {
      algorithm: 'HMAC-SHA256',
      encoding: 'base64',
      payload,
      signature
    });
  } catch (err) {
    return respond(500, { error: 'Scan failed unexpectedly. Try again shortly.' });
  }
};
