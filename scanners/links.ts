import axios from 'axios';
import https from 'node:https';
import { v4 as uuidv4 } from 'uuid';
import * as cheerio from 'cheerio';
import type { Finding } from '../types/scan';

const MAX_LINKS = 40;
const TIMEOUT = 6000;

// Reuse the same SSRF block from middleware — don't follow links to private IPs
const BLOCKED_HOSTS = [
  /^localhost$/i, /^127\./, /^0\./, /^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./,
  /^169\.254\./, /^::1$/, /^fc00:/i, /^fe80:/i, /^0\.0\.0\.0$/,
];

function isSafeLink(href: string): boolean {
  try {
    const u = new URL(href);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    return !BLOCKED_HOSTS.some(p => p.test(u.hostname.toLowerCase()));
  } catch { return false; }
}

interface LinkResult {
  href: string;
  status: number | null;
  type: 'internal' | 'external';
  error?: string;
}

async function checkLink(href: string): Promise<LinkResult['status']> {
  try {
    const { status } = await axios.head(href, {
      timeout: TIMEOUT,
      maxRedirects: 5,
      validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; RibbyScanner/1.0)' },
      httpsAgent: new https.Agent({ rejectUnauthorized: false })
    });
    return status;
  } catch {
    try {
      // fallback to GET if HEAD not supported
      const { status } = await axios.get(href, {
        timeout: TIMEOUT,
        maxRedirects: 5,
        validateStatus: () => true,
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; RibbyScanner/1.0)' },
        httpsAgent: new https.Agent({ rejectUnauthorized: false })
      });
      return status;
    } catch {
      return null;
    }
  }
}

export async function runBrokenLinksScan(url: string, html: string, onProgress: (p: number) => void): Promise<Finding[]> {
  const findings: Finding[] = [];
  const $ = cheerio.load(html);

  let origin = '';
  try { origin = new URL(url).origin; } catch { return findings; }

  // Collect all links
  const rawLinks = new Set<string>();
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href') || '';
    if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:')) return;
    try {
      const abs = href.startsWith('http') ? href : new URL(href, url).href;
      if (isSafeLink(abs)) rawLinks.add(abs);
    } catch { /* invalid URL */ }
  });

  // Also check common resource links
  $('link[href], script[src], img[src]').each((_, el) => {
    const href = $(el).attr('href') || $(el).attr('src') || '';
    if (!href || href.startsWith('data:')) return;
    try {
      const abs = href.startsWith('http') ? href : new URL(href, url).href;
      if (isSafeLink(abs)) rawLinks.add(abs);
    } catch { /* */ }
  });

  const allLinks = Array.from(rawLinks).slice(0, MAX_LINKS);
  const internalLinks = allLinks.filter(l => l.startsWith(origin));
  const externalLinks = allLinks.filter(l => !l.startsWith(origin));

  if (allLinks.length === 0) {
    findings.push({ id: uuidv4(), title: 'No Links Found on Page', description: 'No crawlable links were found on this page.', severity: 'info', category: 'functional', location: url, recommendation: 'Ensure navigation and content links are in standard <a href="..."> tags.' });
    return findings;
  }

  onProgress(20);

  // Check links in batches of 5
  const results: LinkResult[] = [];
  const batchSize = 5;

  for (let i = 0; i < allLinks.length; i += batchSize) {
    const batch = allLinks.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(async (href) => {
        const status = await checkLink(href);
        return { href, status, type: href.startsWith(origin) ? 'internal' as const : 'external' as const };
      })
    );
    results.push(...batchResults);
    onProgress(20 + Math.round(((i + batchSize) / allLinks.length) * 70));
  }

  onProgress(95);

  // Analyse results
  const broken = results.filter(r => r.status === null || r.status === 404 || r.status >= 500);
  const redirected = results.filter(r => r.status && r.status >= 300 && r.status < 400);
  const ok = results.filter(r => r.status && r.status >= 200 && r.status < 300);

  // Group broken by type
  const brokenInternal = broken.filter(r => r.type === 'internal');
  const brokenExternal = broken.filter(r => r.type === 'external');

  for (const link of brokenInternal) {
    findings.push({
      id: uuidv4(),
      title: `Broken Internal Link: ${new URL(link.href).pathname}`,
      description: `Internal link returned ${link.status ?? 'no response'}: ${link.href}. Users clicking this link will see an error page.`,
      severity: 'high', category: 'functional', location: link.href,
      recommendation: 'Update or remove this link. If the page was moved, set up a 301 redirect.'
    });
  }

  for (const link of brokenExternal) {
    findings.push({
      id: uuidv4(),
      title: `Broken External Link (${link.status ?? 'unreachable'})`,
      description: `External link is broken: ${link.href}`,
      severity: 'medium', category: 'functional', location: link.href,
      recommendation: 'Remove or replace this external link. Consider using archive.org for historical references.'
    });
  }

  if (redirected.length > 3) {
    findings.push({
      id: uuidv4(),
      title: `${redirected.length} Links Have Redirect Chains`,
      description: `${redirected.length} links return 3xx redirects. Redirect chains slow down page loads and dilute link equity.`,
      severity: 'low', category: 'functional', location: 'Multiple links',
      recommendation: 'Update links to point directly to the final destination URL, eliminating redirect hops.'
    });
  }

  // Summary finding
  findings.unshift({
    id: uuidv4(),
    title: `Link Check Complete: ${allLinks.length} links scanned`,
    description: `Checked ${allLinks.length} links (${internalLinks.length} internal, ${externalLinks.length} external). ${ok.length} OK · ${broken.length} broken · ${redirected.length} redirects.`,
    severity: broken.length === 0 ? 'info' : broken.some(b => b.type === 'internal') ? 'high' : 'medium',
    category: 'functional', location: url,
    recommendation: broken.length === 0 ? 'All checked links are healthy.' : `Fix ${brokenInternal.length} internal and ${brokenExternal.length} external broken links.`
  });

  onProgress(100);
  return findings;
}
