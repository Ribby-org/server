import { Finding } from '../../client/src/types/scan';
import { v4 as uuidv4 } from 'uuid';
import * as cheerio from 'cheerio';

export function runFunctionalScan(url: string, html: string, headers: Record<string, string>, statusCode: number, redirectCount: number): Finding[] {
  const findings: Finding[] = [];
  const $ = cheerio.load(html);

  if (statusCode >= 500) {
    findings.push({ id: uuidv4(), title: `Server Error: HTTP ${statusCode}`, description: `The server returned ${statusCode}. Users cannot access the application.`, severity: 'critical', category: 'functional', location: url, recommendation: 'Check server logs, fix the underlying error, set up error monitoring.' });
  } else if (statusCode >= 400) {
    findings.push({ id: uuidv4(), title: `Client Error: HTTP ${statusCode}`, description: `The server returned ${statusCode}. The resource may be missing or require authentication.`, severity: 'high', category: 'functional', location: url, recommendation: 'Verify the URL is correct and the resource exists.' });
  }

  if (redirectCount > 3) {
    findings.push({ id: uuidv4(), title: `Excessive Redirects (${redirectCount})`, description: `${redirectCount} redirects before reaching the final page. Adds latency and confuses crawlers.`, severity: 'medium', category: 'functional', location: url, recommendation: 'Reduce redirect chains to 1–2 hops. Update links to point to the final URL.' });
  }

  const metaDesc = $('meta[name="description"]').attr('content');
  if (!metaDesc?.trim()) {
    findings.push({ id: uuidv4(), title: 'Missing Meta Description', description: 'No meta description found. Search engines display this in results — missing it reduces click-through rates.', severity: 'low', category: 'functional', location: '<head>', recommendation: 'Add: <meta name="description" content="150–160 char description">' });
  }

  let unsafeForms = 0;
  $('form').each((_, el) => {
    const method = ($(el).attr('method') || 'get').toLowerCase();
    if (method === 'post' && !$(el).find('input[name*="csrf"],input[name*="token"],input[name*="_token"]').length) unsafeForms++;
  });
  if (unsafeForms > 0) {
    findings.push({ id: uuidv4(), title: `${unsafeForms} Form(s) Potentially Missing CSRF Protection`, description: `${unsafeForms} POST form(s) with no visible CSRF token. Attackers could submit forms on behalf of authenticated users.`, severity: 'high', category: 'functional', location: '<form> elements', recommendation: 'Add CSRF tokens to all state-changing forms. Most frameworks have built-in support.' });
  }

  if (!$('meta[property="og:title"]').attr('content') || !$('meta[property="og:image"]').attr('content')) {
    findings.push({ id: uuidv4(), title: 'Missing Open Graph Tags', description: 'Links shared on social media will display poorly with no title or image preview.', severity: 'info', category: 'functional', location: '<head>', recommendation: 'Add og:title, og:description, og:image, og:url meta tags.' });
  }

  if (!$('link[rel*="icon"]').length && !html.includes('favicon.ico')) {
    findings.push({ id: uuidv4(), title: 'Missing Favicon', description: 'No favicon detected. Browsers show a blank tab icon, reducing brand recognition.', severity: 'info', category: 'functional', location: '<head>', recommendation: 'Add: <link rel="icon" type="image/png" href="/favicon.png">' });
  }

  const deprecated = ['<center', '<font ', '<marquee', '<blink', '<frameset'];
  const found = deprecated.filter(t => html.toLowerCase().includes(t));
  if (found.length > 0) {
    findings.push({ id: uuidv4(), title: 'Deprecated HTML Elements', description: `Found deprecated tags: ${found.join(', ')}. Not supported in modern browsers.`, severity: 'low', category: 'functional', location: 'Page HTML', recommendation: 'Replace deprecated elements with modern CSS equivalents.' });
  }

  return findings;
}
