import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import * as cheerio from 'cheerio';
import type { Finding } from '../../client/src/types/scan';

export async function runSeoScan(url: string, html: string, headers: Record<string, string>): Promise<Finding[]> {
  const findings: Finding[] = [];
  const $ = cheerio.load(html);

  let baseUrl = url;
  try { baseUrl = new URL(url).origin; } catch { /* */ }

  // 1. Title tag
  const title = $('title').text().trim();
  if (!title) {
    findings.push({ id: uuidv4(), title: 'Missing Page Title', description: 'No <title> tag found. Search engines use the title as the primary clickable headline in results.', severity: 'high', category: 'functional', location: '<head>', recommendation: 'Add a descriptive <title> between 50–60 characters.' });
  } else if (title.length < 30) {
    findings.push({ id: uuidv4(), title: `Page Title Too Short (${title.length} chars)`, description: `Title "${title}" is too short. Titles under 30 characters don't give search engines enough context.`, severity: 'medium', category: 'functional', location: '<title>', recommendation: 'Expand the title to 50–60 characters to improve click-through rates.' });
  } else if (title.length > 60) {
    findings.push({ id: uuidv4(), title: `Page Title Too Long (${title.length} chars)`, description: `Title "${title.substring(0, 60)}…" is ${title.length} characters. Google truncates titles above ~60 chars in search results.`, severity: 'low', category: 'functional', location: '<title>', recommendation: 'Trim the title to under 60 characters.' });
  }

  // 2. Meta description
  const metaDesc = $('meta[name="description"]').attr('content') || '';
  if (!metaDesc.trim()) {
    findings.push({ id: uuidv4(), title: 'Missing Meta Description', description: 'No meta description found. Google often uses this as the snippet text in search results.', severity: 'high', category: 'functional', location: '<meta name="description">', recommendation: 'Add a compelling meta description of 150–160 characters.' });
  } else if (metaDesc.length < 70) {
    findings.push({ id: uuidv4(), title: `Meta Description Too Short (${metaDesc.length} chars)`, description: 'Meta description is too short to be useful in search results.', severity: 'low', category: 'functional', location: '<meta name="description">', recommendation: 'Expand the description to 150–160 characters.' });
  } else if (metaDesc.length > 160) {
    findings.push({ id: uuidv4(), title: `Meta Description Too Long (${metaDesc.length} chars)`, description: `Description is ${metaDesc.length} characters — Google truncates at ~160 chars in search snippets.`, severity: 'low', category: 'functional', location: '<meta name="description">', recommendation: 'Trim the meta description to under 160 characters.' });
  }

  // 3. Canonical URL
  const canonical = $('link[rel="canonical"]').attr('href');
  if (!canonical) {
    findings.push({ id: uuidv4(), title: 'Missing Canonical URL', description: 'No canonical link tag found. Without it, duplicate content across URLs can split SEO ranking signals.', severity: 'medium', category: 'functional', location: '<head>', recommendation: `Add a canonical tag in <head> pointing to the preferred URL of this page. Example: <link rel="canonical" href="${url}">. This tells search engines which URL to index when the same content is accessible at multiple addresses.` });
  }

  // 4. robots.txt
  try {
    const { data, status } = await axios.get(`${baseUrl}/robots.txt`, { timeout: 5000, validateStatus: () => true });
    if (status === 404) {
      findings.push({ id: uuidv4(), title: 'robots.txt Not Found', description: 'No robots.txt file found. Search engines crawl without guidance, potentially indexing unwanted pages.', severity: 'medium', category: 'functional', location: '/robots.txt', recommendation: 'Create a robots.txt file to control crawler access.' });
    } else if (typeof data === 'string' && data.toLowerCase().includes('disallow: /')) {
      const allBlocked = data.match(/disallow:\s*\/\s*$/mi);
      if (allBlocked) {
        findings.push({ id: uuidv4(), title: 'robots.txt Blocking All Crawlers', description: '"Disallow: /" found in robots.txt — this blocks all search engines from indexing your site entirely.', severity: 'critical', category: 'functional', location: '/robots.txt', recommendation: 'Review robots.txt. Remove or limit "Disallow: /" unless intentional.' });
      }
    }
  } catch { /* ignore network errors */ }

  // 5. sitemap.xml
  try {
    const { status } = await axios.get(`${baseUrl}/sitemap.xml`, { timeout: 5000, validateStatus: () => true });
    if (status === 404) {
      findings.push({ id: uuidv4(), title: 'sitemap.xml Not Found', description: 'No sitemap found. Search engines discover pages less efficiently without a sitemap.', severity: 'medium', category: 'functional', location: '/sitemap.xml', recommendation: 'Generate and submit a sitemap.xml. Submit it to Google Search Console.' });
    }
  } catch { /* ignore */ }

  // 6. Structured data
  const jsonLd = $('script[type="application/ld+json"]').length;
  if (jsonLd === 0) {
    findings.push({ id: uuidv4(), title: 'No Structured Data (JSON-LD) Found', description: 'No structured data detected. Structured data enables rich results (stars, breadcrumbs, FAQs) in Google.', severity: 'low', category: 'functional', location: '<script type="application/ld+json">', recommendation: 'Add JSON-LD structured data (Schema.org) relevant to your content type.' });
  }

  // 7. Open Graph
  const ogTitle = $('meta[property="og:title"]').attr('content');
  const ogImage = $('meta[property="og:image"]').attr('content');
  const ogDesc = $('meta[property="og:description"]').attr('content');
  const missing = [!ogTitle && 'og:title', !ogImage && 'og:image', !ogDesc && 'og:description'].filter(Boolean);
  if (missing.length > 0) {
    findings.push({ id: uuidv4(), title: `Missing Open Graph Tags: ${missing.join(', ')}`, description: `Social shares will show no preview. Missing: ${missing.join(', ')}.`, severity: 'low', category: 'functional', location: '<head> Open Graph meta', recommendation: 'Add og:title, og:description, og:image, og:url meta tags for rich social previews.' });
  }

  // 8. Twitter Card
  const twitterCard = $('meta[name="twitter:card"]').attr('content');
  if (!twitterCard) {
    findings.push({ id: uuidv4(), title: 'Missing Twitter Card Meta Tags', description: 'No Twitter Card meta tags found. Links shared on X/Twitter will display without a preview card.', severity: 'info', category: 'functional', location: '<head>', recommendation: 'Add <meta name="twitter:card" content="summary_large_image"> and related tags.' });
  }

  // 9. H1 count
  const h1s = $('h1');
  if (h1s.length === 0) {
    findings.push({ id: uuidv4(), title: 'No H1 Heading Found', description: 'Missing H1 tag. Search engines use H1 as the primary topic signal for the page.', severity: 'high', category: 'functional', location: 'Page content', recommendation: 'Add exactly one <h1> that clearly describes the main topic of the page.' });
  } else if (h1s.length > 1) {
    findings.push({ id: uuidv4(), title: `Multiple H1 Tags Found (${h1s.length})`, description: `Page has ${h1s.length} H1 tags. Multiple H1s dilute topic focus and confuse crawlers.`, severity: 'medium', category: 'functional', location: 'Page content', recommendation: 'Use exactly one H1 per page. Use H2–H6 for subheadings.' });
  }

  // 10. Image alt text (SEO angle)
  let imgsWithoutAlt = 0;
  $('img').each((_, el) => { if (!$(el).attr('alt')) imgsWithoutAlt++; });
  if (imgsWithoutAlt > 0) {
    findings.push({ id: uuidv4(), title: `${imgsWithoutAlt} Image(s) Missing Alt Text`, description: `${imgsWithoutAlt} images have no alt attribute. Alt text is an important signal for image search ranking.`, severity: 'medium', category: 'functional', location: '<img> elements', recommendation: 'Add descriptive alt text to all content images. Use alt="" for decorative images.' });
  }

  // 11. Viewport
  if (!$('meta[name="viewport"]').attr('content')) {
    findings.push({ id: uuidv4(), title: 'Missing Viewport Meta Tag', description: 'No viewport tag found. Google uses mobile-friendliness as a ranking factor.', severity: 'high', category: 'functional', location: '<head>', recommendation: 'Add: <meta name="viewport" content="width=device-width, initial-scale=1">' });
  }

  // 12. hreflang (if multi-language signals exist)
  const hreflang = $('link[rel="alternate"][hreflang]').length;
  const hasLangSignals = html.includes('lang=') || url.includes('/en/') || url.includes('/fr/');
  if (hasLangSignals && hreflang === 0) {
    findings.push({ id: uuidv4(), title: 'Possible Multi-language Site Missing hreflang Tags', description: 'Language signals detected but no hreflang alternate links found. Without hreflang, Google may show the wrong language version to users.', severity: 'medium', category: 'functional', location: '<head>', recommendation: 'Add <link rel="alternate" hreflang="x"> tags for each language/region variant.' });
  }

  return findings;
}
