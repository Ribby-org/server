import { Finding, Severity } from '../types/scan';
import { v4 as uuidv4 } from 'uuid';

const SECURITY_HEADERS: Record<string, { title: string; description: string; severity: Severity; recommendation: string }> = {
  'content-security-policy': {
    title: 'Missing Content-Security-Policy Header',
    description: 'CSP header is absent, leaving the site vulnerable to XSS and data injection attacks.',
    severity: 'high',
    recommendation: "Add: Content-Security-Policy: default-src 'self'; script-src 'self'"
  },
  'x-frame-options': {
    title: 'Missing X-Frame-Options Header',
    description: 'Without this header, attackers can embed your site in an iframe to perform clickjacking attacks.',
    severity: 'medium',
    recommendation: 'Add: X-Frame-Options: DENY'
  },
  'x-content-type-options': {
    title: 'Missing X-Content-Type-Options Header',
    description: 'Browsers may sniff MIME types, allowing attackers to trick the browser into executing malicious content.',
    severity: 'low',
    recommendation: 'Add: X-Content-Type-Options: nosniff'
  },
  'strict-transport-security': {
    title: 'Missing HSTS Header',
    description: 'HTTP Strict Transport Security is not configured. Users may connect over insecure HTTP.',
    severity: 'high',
    recommendation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
  },
  'referrer-policy': {
    title: 'Missing Referrer-Policy Header',
    description: 'Sensitive URL data may leak to third-party sites via the Referer header.',
    severity: 'low',
    recommendation: 'Add: Referrer-Policy: strict-origin-when-cross-origin'
  },
  'permissions-policy': {
    title: 'Missing Permissions-Policy Header',
    description: 'No restrictions on browser features like camera, microphone, and geolocation.',
    severity: 'low',
    recommendation: 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()'
  }
};

export function runSecurityScan(url: string, html: string, headers: Record<string, string>): Finding[] {
  const findings: Finding[] = [];

  if (!url.startsWith('https://')) {
    findings.push({
      id: uuidv4(), title: 'Site Not Served Over HTTPS',
      description: 'All traffic is in plaintext, exposing users to man-in-the-middle attacks.',
      severity: 'critical', category: 'security', location: url,
      recommendation: 'Install an SSL/TLS certificate and redirect all HTTP to HTTPS.'
    });
  }

  for (const [header, check] of Object.entries(SECURITY_HEADERS)) {
    if (!headers[header]) {
      findings.push({ id: uuidv4(), ...check, category: 'security', location: 'HTTP Response Headers' });
    }
  }

  const serverHeader = headers['server'] || headers['x-powered-by'];
  if (serverHeader && /\d/.test(serverHeader)) {
    findings.push({
      id: uuidv4(), title: 'Server Version Disclosed',
      description: `Server header reveals software version: "${serverHeader}". Attackers use this to find known exploits.`,
      severity: 'low', category: 'security', location: 'HTTP Headers → Server',
      recommendation: 'Configure your server to omit version info from the Server and X-Powered-By headers.'
    });
  }

  if (headers['access-control-allow-origin'] === '*') {
    findings.push({
      id: uuidv4(), title: 'CORS Wildcard Origin',
      description: 'The server allows cross-origin requests from any domain, potentially exposing sensitive API data.',
      severity: 'medium', category: 'security', location: 'HTTP Headers → Access-Control-Allow-Origin',
      recommendation: 'Restrict CORS to specific trusted origins instead of using a wildcard.'
    });
  }

  if (url.startsWith('https://')) {
    const mixed = (html.match(/(?:src|href|action)=["']http:\/\//gi) || []).length;
    if (mixed > 0) {
      findings.push({
        id: uuidv4(), title: 'Mixed Content Detected',
        description: `Found ${mixed} resource(s) loaded over HTTP on an HTTPS page. Browsers block these or warn users.`,
        severity: 'medium', category: 'security', location: 'Page HTML',
        recommendation: 'Update all embedded resource URLs to HTTPS.'
      });
    }
  }

  const sensitive = [
    { pattern: /api[_-]?key\s*[:=]\s*["'][^"']{8,}/i, label: 'API key in source' },
    { pattern: /password\s*[:=]\s*["'][^"']+["']/i, label: 'Hardcoded password' },
    { pattern: /secret\s*[:=]\s*["'][^"']{6,}["']/i, label: 'Hardcoded secret' }
  ];
  for (const { pattern, label } of sensitive) {
    if (pattern.test(html)) {
      findings.push({
        id: uuidv4(), title: `Sensitive Data Exposed: ${label}`,
        description: `The page source may contain ${label} visible in client-side code.`,
        severity: 'critical', category: 'security', location: 'Page HTML/JS Source',
        recommendation: 'Remove all credentials from client-side code. Use server-side environment variables.'
      });
    }
  }

  return findings;
}
