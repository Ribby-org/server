import { Finding } from '../../client/src/types/scan';
import { v4 as uuidv4 } from 'uuid';

export function runPerformanceScan(html: string, headers: Record<string, string>, responseTime: number, contentSize: number): Finding[] {
  const findings: Finding[] = [];

  if (responseTime > 3000) {
    findings.push({ id: uuidv4(), title: 'Very Slow Server Response', description: `Server took ${(responseTime / 1000).toFixed(2)}s. Above 3s significantly hurts user retention and SEO.`, severity: 'critical', category: 'performance', location: 'Server Response', recommendation: 'Enable server-side caching, optimize database queries, or use a CDN.' });
  } else if (responseTime > 1500) {
    findings.push({ id: uuidv4(), title: 'Slow Server Response', description: `Server responded in ${(responseTime / 1000).toFixed(2)}s. Google recommends TTFB under 800ms.`, severity: 'high', category: 'performance', location: 'Server Response', recommendation: 'Enable caching, optimize backend queries, consider a CDN.' });
  } else if (responseTime > 800) {
    findings.push({ id: uuidv4(), title: 'Moderate Response Time', description: `Server responded in ${(responseTime / 1000).toFixed(2)}s. Aim for under 800ms.`, severity: 'medium', category: 'performance', location: 'Server Response', recommendation: 'Review backend performance and add caching layers.' });
  }

  const enc = headers['content-encoding'];
  if ((!enc || !/(gzip|br|deflate)/.test(enc)) && contentSize > 10000) {
    findings.push({ id: uuidv4(), title: 'HTTP Compression Not Enabled', description: `Content sent uncompressed (${(contentSize / 1024).toFixed(1)} KB). Gzip/Brotli reduces transfer size by 60–80%.`, severity: 'high', category: 'performance', location: 'HTTP Headers', recommendation: 'Enable gzip or Brotli on your web server (nginx: gzip on; Apache: mod_deflate).' });
  }

  if (!headers['cache-control'] && !headers['expires']) {
    findings.push({ id: uuidv4(), title: 'No Caching Headers', description: 'Browser caching is not configured. Every visit forces a full reload.', severity: 'medium', category: 'performance', location: 'HTTP Headers', recommendation: 'Add Cache-Control headers (e.g. Cache-Control: public, max-age=86400 for static assets).' });
  }

  const blockingScripts = (html.match(/<script(?![^>]*defer)(?![^>]*async)[^>]*src=/gi) || []).length;
  if (blockingScripts > 2) {
    findings.push({ id: uuidv4(), title: 'Render-Blocking Scripts', description: `Found ${blockingScripts} synchronous <script> tags that block page rendering.`, severity: 'high', category: 'performance', location: 'HTML Content', recommendation: 'Add defer or async to non-critical scripts: <script src="..." defer>.' });
  }

  if (contentSize > 1000000) {
    findings.push({ id: uuidv4(), title: 'Excessive Page Size', description: `HTML response is ${(contentSize / 1024).toFixed(1)} KB — too large, especially on mobile.`, severity: 'high', category: 'performance', location: 'Page Content', recommendation: 'Remove inline CSS/JS, enable compression, lazy-load content.' });
  }

  if (!html.match(/<meta[^>]*name=["']viewport["']/i)) {
    findings.push({ id: uuidv4(), title: 'Missing Viewport Meta Tag', description: 'Mobile browsers will render at desktop width and scale down, causing layout issues.', severity: 'medium', category: 'performance', location: 'HTML <head>', recommendation: 'Add: <meta name="viewport" content="width=device-width, initial-scale=1">' });
  }

  const lazyImages = (html.match(/<img(?![^>]*loading=["']lazy["'])[^>]*>/gi) || []).length;
  if (lazyImages > 3) {
    findings.push({ id: uuidv4(), title: `${lazyImages} Images Not Lazy-Loaded`, description: `Off-screen images load on page load unnecessarily, wasting bandwidth.`, severity: 'low', category: 'performance', location: 'HTML Content', recommendation: 'Add loading="lazy" to images below the fold.' });
  }

  return findings;
}
