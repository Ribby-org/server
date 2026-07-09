import { v4 as uuidv4 } from 'uuid';
import type { Finding } from '../types/scan';

// ── Known cryptojacking script signatures ─────────────────────────────────────
const CRYPTO_JACKING_PATTERNS = [
  { name: 'CoinHive',          pattern: /coinhive\.min\.js|coinhive\.com/gi },
  { name: 'CryptoLoot',        pattern: /crypto-loot\.com|cryptoloot/gi },
  { name: 'JSEcoin',           pattern: /jsecoin\.com/gi },
  { name: 'DeepMiner',         pattern: /deepminer\.js|deepminer\.co/gi },
  { name: 'MineroGate',        pattern: /minerogate\.com/gi },
  { name: 'Monero WebMiner',   pattern: /monero.*miner|xmr.*miner|webminer/gi },
  { name: 'Generic WebSocket Miner', pattern: /wss?:\/\/[^\s"']+(?:mine|pool|stratum)/gi },
  { name: 'Stratum Mining Pool',     pattern: /stratum\+tcp|stratum\+ssl/gi },
];

// ── Weak cryptographic algorithm patterns ─────────────────────────────────────
const WEAK_CRYPTO_PATTERNS = [
  {
    pattern: /md5\s*\(|createHash\s*\(\s*['"]md5['"]\s*\)/gi,
    name: 'MD5 Hash Usage',
    desc: 'MD5 is cryptographically broken and unsuitable for security use. Detected in page scripts.',
    severity: 'high' as const,
    fix: 'Replace MD5 with SHA-256 or SHA-3 for any security-sensitive hashing.'
  },
  {
    pattern: /sha1\s*\(|createHash\s*\(\s*['"]sha1['"]\s*\)/gi,
    name: 'SHA-1 Hash Usage',
    desc: 'SHA-1 is deprecated and vulnerable to collision attacks. Detected in page scripts.',
    severity: 'high' as const,
    fix: 'Replace SHA-1 with SHA-256 or better.'
  },
  {
    pattern: /DES\.encrypt|createCipheriv\s*\(\s*['"]des/gi,
    name: 'DES Encryption Usage',
    desc: 'DES uses a 56-bit key and has been broken since 1999. Detected in page scripts.',
    severity: 'critical' as const,
    fix: 'Replace DES with AES-256-GCM or ChaCha20-Poly1305.'
  },
  {
    pattern: /RC4|createCipheriv\s*\(\s*['"]rc4/gi,
    name: 'RC4 Cipher Usage',
    desc: 'RC4 is a broken stream cipher with multiple known vulnerabilities.',
    severity: 'critical' as const,
    fix: 'Replace RC4 with AES-256-GCM.'
  },
  {
    pattern: /Math\.random\s*\(\s*\).*(?:token|secret|key|session|nonce|salt|password|csrf)/gi,
    name: 'Math.random() for Security',
    desc: 'Math.random() is not cryptographically secure and must not be used for tokens, keys, or secrets.',
    severity: 'critical' as const,
    fix: 'Use window.crypto.getRandomValues() or crypto.randomBytes() for security-sensitive randomness.'
  },
  {
    pattern: /(?:token|secret|key|session|nonce|salt|password|csrf).*Math\.random\s*\(\s*\)/gi,
    name: 'Math.random() for Security (reversed)',
    desc: 'Math.random() is not cryptographically secure and must not be used for tokens, keys, or secrets.',
    severity: 'critical' as const,
    fix: 'Use window.crypto.getRandomValues() or crypto.randomBytes() for security-sensitive randomness.'
  },
  {
    pattern: /createCipheriv\s*\(\s*['"]aes-\d+-ecb/gi,
    name: 'AES-ECB Mode',
    desc: 'AES in ECB mode is insecure — identical plaintext blocks produce identical ciphertext, leaking patterns.',
    severity: 'high' as const,
    fix: 'Use AES-GCM or AES-CBC with a random IV instead of ECB mode.'
  },
];

// ── JWT vulnerability patterns ─────────────────────────────────────────────────
const JWT_PATTERNS = [
  {
    pattern: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/g,
    name: 'JWT Token Exposed in Page',
    desc: 'A JWT token was found embedded in the page HTML or scripts. Exposing tokens in markup is a security risk.',
    severity: 'high' as const,
    fix: 'Never embed JWT tokens in HTML. Store them in HttpOnly cookies or memory only.'
  },
  {
    pattern: /"alg"\s*:\s*"none"/gi,
    name: 'JWT "alg: none" Vulnerability',
    desc: 'A JWT with algorithm set to "none" was detected. This completely disables signature verification.',
    severity: 'critical' as const,
    fix: 'Always use a strong algorithm such as RS256 or HS256. Reject JWTs with "alg: none" on the server.'
  },
  {
    pattern: /"alg"\s*:\s*"HS256".*"secret"\s*:\s*"(?:secret|password|123|test|key)"/gi,
    name: 'Weak JWT Secret',
    desc: 'A JWT signed with a weak or guessable secret was detected.',
    severity: 'critical' as const,
    fix: 'Use a cryptographically random secret of at least 256 bits for HS256, or switch to RS256.'
  },
];

// ── Subresource Integrity check ───────────────────────────────────────────────
function checkSRI(html: string): Finding[] {
  const findings: Finding[] = [];

  // External scripts without integrity attribute
  const externalScripts = html.matchAll(/<script[^>]+src=["']https?:\/\/(?!localhost)[^"']+["'][^>]*>/gi);
  const missingIntegrity: string[] = [];

  for (const match of externalScripts) {
    const tag = match[0];
    if (!/integrity=/i.test(tag) && !/nonce=/i.test(tag)) {
      const srcMatch = tag.match(/src=["']([^"']+)["']/i);
      if (srcMatch) missingIntegrity.push(srcMatch[1]);
    }
  }

  if (missingIntegrity.length > 0) {
    findings.push({
      id: uuidv4(),
      title: `${missingIntegrity.length} External Script${missingIntegrity.length > 1 ? 's' : ''} Missing Subresource Integrity`,
      description: `External scripts loaded without an integrity attribute cannot be verified. A compromised CDN could inject malicious code. Affected: ${missingIntegrity.slice(0, 3).join(', ')}${missingIntegrity.length > 3 ? ` +${missingIntegrity.length - 3} more` : ''}`,
      severity: 'high',
      category: 'security',
      location: 'Page HTML — <script> tags',
      recommendation: 'Add integrity="sha384-..." and crossorigin="anonymous" to all external scripts. Generate SRI hashes at https://www.srihash.org/'
    });
  }

  return findings;
}

// ── Cookie crypto flags ───────────────────────────────────────────────────────
function checkCookieFlags(headers: Record<string, string>): Finding[] {
  const findings: Finding[] = [];
  const setCookie = headers['set-cookie'] || '';

  if (setCookie) {
    if (!/httponly/i.test(setCookie)) {
      findings.push({
        id: uuidv4(),
        title: 'Session Cookie Missing HttpOnly Flag',
        description: 'Cookies without HttpOnly can be accessed by JavaScript, enabling token theft via XSS.',
        severity: 'high',
        category: 'security',
        location: 'HTTP Response — Set-Cookie header',
        recommendation: 'Add the HttpOnly flag to all session and auth cookies: Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict'
      });
    }

    if (!/samesite/i.test(setCookie)) {
      findings.push({
        id: uuidv4(),
        title: 'Cookie Missing SameSite Attribute',
        description: 'Without SameSite, cookies are sent on cross-site requests, enabling CSRF attacks.',
        severity: 'medium',
        category: 'security',
        location: 'HTTP Response — Set-Cookie header',
        recommendation: 'Add SameSite=Strict or SameSite=Lax to all cookies.'
      });
    }
  }

  return findings;
}

// ── Main crypto scanner ───────────────────────────────────────────────────────
export function runCryptoScan(url: string, html: string, headers: Record<string, string>): Finding[] {
  const findings: Finding[] = [];

  // 1. Cryptojacking detection
  for (const { name, pattern } of CRYPTO_JACKING_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(html)) {
      findings.push({
        id: uuidv4(),
        title: `Cryptojacking Script Detected: ${name}`,
        description: `A known cryptocurrency mining script (${name}) was found embedded in the page. This silently uses visitors' CPU to mine cryptocurrency without consent.`,
        severity: 'critical',
        category: 'security',
        location: 'Page HTML/JS',
        recommendation: 'Remove the mining script immediately. Audit all third-party scripts and use Content-Security-Policy to block unauthorized scripts.'
      });
    }
  }

  // 2. Weak crypto algorithm detection
  const seen = new Set<string>();
  for (const { pattern, name, desc, severity, fix } of WEAK_CRYPTO_PATTERNS) {
    pattern.lastIndex = 0;
    if (!seen.has(name) && pattern.test(html)) {
      seen.add(name);
      findings.push({
        id: uuidv4(),
        title: `Weak Cryptography: ${name}`,
        description: desc,
        severity,
        category: 'security',
        location: 'Page JavaScript',
        recommendation: fix
      });
    }
  }

  // 3. JWT vulnerability detection
  for (const { pattern, name, desc, severity, fix } of JWT_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(html)) {
      findings.push({
        id: uuidv4(),
        title: name,
        description: desc,
        severity,
        category: 'security',
        location: 'Page HTML/JS',
        recommendation: fix
      });
    }
  }

  // 4. Subresource Integrity
  findings.push(...checkSRI(html));

  // 5. Cookie flags
  findings.push(...checkCookieFlags(headers));

  // 6. HTTPS check specific to crypto
  if (!url.startsWith('https://')) {
    findings.push({
      id: uuidv4(),
      title: 'Unencrypted Channel — All Crypto Protections Bypassed',
      description: 'Without HTTPS, all cryptographic protections in the browser are void. An attacker can intercept and modify all data in transit, including tokens and passwords.',
      severity: 'critical',
      category: 'security',
      location: url,
      recommendation: 'Enforce HTTPS site-wide. Obtain a TLS certificate (free via Let\'s Encrypt) and redirect all HTTP to HTTPS.'
    });
  }

  // 7. If no issues found
  if (findings.length === 0) {
    findings.push({
      id: uuidv4(),
      title: 'No Cryptographic Vulnerabilities Detected',
      description: 'No cryptojacking scripts, weak algorithms, exposed tokens, or missing integrity checks were found.',
      severity: 'info',
      category: 'security',
      location: url,
      recommendation: 'Continue using strong cryptographic practices and keep dependencies up to date.'
    });
  }

  return findings;
}
