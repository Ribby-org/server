import https from 'https';
import tls from 'tls';
import { v4 as uuidv4 } from 'uuid';
import type { Finding } from '../types/scan';

function getCertInfo(hostname: string): Promise<tls.PeerCertificate & { valid_from: string; valid_to: string; subject: Record<string, string>; issuer: Record<string, string> }> {
  return new Promise((resolve, reject) => {
    const req = https.get({
      hostname,
      port: 443,
      path: '/',
      rejectUnauthorized: false,
      timeout: 8000,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; RibbyScanner/1.0)' }
    }, (res) => {
      const socket = res.socket as tls.TLSSocket;
      const cert = socket.getPeerCertificate() as any;
      req.destroy();
      resolve(cert);
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('SSL connection timed out')); });
  });
}

export async function runSslScan(url: string, headers: Record<string, string>): Promise<Finding[]> {
  const findings: Finding[] = [];

  let hostname = '';
  try { hostname = new URL(url).hostname; } catch {
    findings.push({ id: uuidv4(), title: 'Invalid URL', description: 'Could not parse the URL to extract hostname.', severity: 'critical', category: 'security', recommendation: 'Check the URL format.' });
    return findings;
  }

  // 1. HTTPS check
  if (!url.startsWith('https://')) {
    findings.push({ id: uuidv4(), title: 'Site Not Using HTTPS', description: 'The site is served over HTTP. All data is transmitted in plaintext.', severity: 'critical', category: 'security', location: url, recommendation: 'Install an SSL/TLS certificate and redirect all HTTP to HTTPS.' });
    return findings;
  }

  // 2. Certificate details
  let cert: any;
  try {
    cert = await getCertInfo(hostname);
  } catch (err: any) {
    findings.push({ id: uuidv4(), title: 'SSL Certificate Unreachable', description: `Could not connect to retrieve SSL certificate: ${err.message}`, severity: 'critical', category: 'security', location: `${hostname}:443`, recommendation: 'Ensure port 443 is open and a valid SSL certificate is installed.' });
    return findings;
  }

  if (!cert || !cert.valid_to) {
    findings.push({ id: uuidv4(), title: 'SSL Certificate Invalid or Self-Signed', description: 'Could not retrieve a valid certificate. The site may be using a self-signed or misconfigured certificate.', severity: 'critical', category: 'security', location: hostname, recommendation: 'Install a certificate from a trusted Certificate Authority (CA).' });
    return findings;
  }

  // 3. Expiry
  const expiryDate = new Date(cert.valid_to);
  const now = new Date();
  const daysLeft = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

  if (daysLeft < 0) {
    findings.push({ id: uuidv4(), title: 'SSL Certificate Has Expired', description: `Certificate expired ${Math.abs(daysLeft)} day(s) ago on ${expiryDate.toDateString()}. Browsers show a security warning — users cannot safely access the site.`, severity: 'critical', category: 'security', location: hostname, recommendation: 'Renew the SSL certificate immediately. Use Let\'s Encrypt for free auto-renewal.' });
  } else if (daysLeft <= 7) {
    findings.push({ id: uuidv4(), title: `SSL Certificate Expires in ${daysLeft} Day(s)`, description: `Certificate expires on ${expiryDate.toDateString()}. Site will show security errors in ${daysLeft} days.`, severity: 'critical', category: 'security', location: hostname, recommendation: 'Renew immediately. Enable auto-renewal to prevent future expiry.' });
  } else if (daysLeft <= 30) {
    findings.push({ id: uuidv4(), title: `SSL Certificate Expiring Soon (${daysLeft} days)`, description: `Certificate expires on ${expiryDate.toDateString()}. Renew before it expires to avoid downtime.`, severity: 'high', category: 'security', location: hostname, recommendation: 'Renew the certificate now. Set up auto-renewal (e.g. Certbot with Let\'s Encrypt).' });
  } else {
    findings.push({ id: uuidv4(), title: `SSL Certificate Valid (${daysLeft} days remaining)`, description: `Certificate expires on ${expiryDate.toDateString()}. Issued by: ${cert.issuer?.O || cert.issuer?.CN || 'Unknown CA'}.`, severity: 'info', category: 'security', location: hostname, recommendation: 'Certificate is healthy. Ensure auto-renewal is configured.' });
  }

  // 4. Certificate issuer
  const issuer = cert.issuer?.O || cert.issuer?.CN || '';
  if (issuer.toLowerCase().includes('self-signed') || (cert.issuer?.CN === cert.subject?.CN)) {
    findings.push({ id: uuidv4(), title: 'Possible Self-Signed Certificate', description: 'The certificate appears to be self-signed (issuer = subject). Browsers will show a security warning to all visitors.', severity: 'critical', category: 'security', location: hostname, recommendation: 'Replace with a certificate from a trusted CA. Use Let\'s Encrypt (free).' });
  }

  // 5. HSTS header
  const hsts = headers['strict-transport-security'];
  if (!hsts) {
    findings.push({ id: uuidv4(), title: 'HSTS Not Configured', description: 'Strict-Transport-Security header is missing. Browsers may allow HTTP connections, exposing users to downgrade attacks.', severity: 'high', category: 'security', location: 'HTTP Headers', recommendation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' });
  } else {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
    if (maxAge < 2592000) {
      findings.push({ id: uuidv4(), title: `HSTS max-age Too Short (${maxAge}s)`, description: `HSTS max-age is ${maxAge} seconds (~${Math.floor(maxAge / 86400)} days). Google recommends at least 1 year (31536000s).`, severity: 'medium', category: 'security', location: 'HTTP Headers → Strict-Transport-Security', recommendation: 'Set max-age to at least 31536000 (1 year) and add includeSubDomains; preload.' });
    }
    if (!hsts.includes('includeSubDomains')) {
      findings.push({ id: uuidv4(), title: 'HSTS Missing includeSubDomains', description: 'HSTS does not include subdomains. Subdomains can still be accessed over HTTP.', severity: 'medium', category: 'security', location: 'HTTP Headers', recommendation: 'Add includeSubDomains to your HSTS header.' });
    }
  }

  // 6. Mixed content
  const csp = headers['content-security-policy'] || '';
  if (csp.includes('http://')) {
    findings.push({ id: uuidv4(), title: 'CSP Allows HTTP Resources', description: 'Content-Security-Policy contains http:// sources, potentially allowing mixed content.', severity: 'medium', category: 'security', location: 'Content-Security-Policy header', recommendation: 'Update CSP to use https:// only for all directives.' });
  }

  return findings;
}
