import { Finding } from '../types/scan';
import { v4 as uuidv4 } from 'uuid';
import * as cheerio from 'cheerio';

export function runAccessibilityScan(html: string): Finding[] {
  const findings: Finding[] = [];
  const $ = cheerio.load(html);

  if (!$('html').attr('lang')) {
    findings.push({ id: uuidv4(), title: 'Missing Language Attribute on <html>', description: 'Screen readers cannot determine the page language.', severity: 'medium', category: 'accessibility', location: '<html> element', recommendation: 'Add a lang attribute: <html lang="en">' });
  }

  const missingAlt: string[] = [];
  $('img').each((_, el) => { if ($(el).attr('alt') === undefined) missingAlt.push($(el).attr('src') || 'unknown'); });
  if (missingAlt.length > 0) {
    findings.push({ id: uuidv4(), title: `${missingAlt.length} Image(s) Missing Alt Text`, description: `Found ${missingAlt.length} <img> element(s) without alt attributes. Screen readers cannot describe these.`, severity: missingAlt.length > 5 ? 'high' : 'medium', category: 'accessibility', location: `<img> elements`, recommendation: 'Add descriptive alt text to all images. Use alt="" for decorative ones.' });
  }

  let unlabeled = 0;
  $('input:not([type="hidden"]):not([type="submit"]):not([type="button"])').each((_, el) => {
    const id = $(el).attr('id');
    if (!$(el).attr('aria-label') && !$(el).attr('aria-labelledby') && !(id && $(`label[for="${id}"]`).length)) unlabeled++;
  });
  if (unlabeled > 0) {
    findings.push({ id: uuidv4(), title: `${unlabeled} Form Input(s) Missing Labels`, description: `${unlabeled} input(s) have no label or ARIA attribute. Screen reader users can't understand these fields.`, severity: 'high', category: 'accessibility', location: '<input> elements', recommendation: 'Use <label for="id"> or aria-label on every input.' });
  }

  if (!$('title').text().trim()) {
    findings.push({ id: uuidv4(), title: 'Missing Page Title', description: 'No <title> element found. Screen readers announce the page title when users navigate to it.', severity: 'high', category: 'accessibility', location: '<head> → <title>', recommendation: 'Add a descriptive <title> tag.' });
  }

  const headings: number[] = [];
  $('h1,h2,h3,h4,h5,h6').each((_, el) => {
    const tag = (el as unknown as { tagName: string }).tagName || '';
    headings.push(parseInt(tag.replace('h', ''), 10));
  });
  const h1s = headings.filter(h => h === 1).length;
  if (h1s === 0 && headings.length > 0) {
    findings.push({ id: uuidv4(), title: 'No H1 Heading Found', description: 'Page has headings but no H1. Screen readers use H1 as the main landmark.', severity: 'medium', category: 'accessibility', location: 'Page heading structure', recommendation: 'Add exactly one <h1> describing the main content.' });
  } else if (h1s > 1) {
    findings.push({ id: uuidv4(), title: `Multiple H1 Headings (${h1s})`, description: `${h1s} H1 headings found. Multiple H1s confuse screen readers and hurt SEO.`, severity: 'low', category: 'accessibility', location: 'Page heading structure', recommendation: 'Use exactly one <h1> per page.' });
  }

  let emptyLinks = 0;
  $('a').each((_, el) => {
    if (!$(el).text().trim() && !$(el).attr('aria-label') && !$(el).find('img').attr('alt')) emptyLinks++;
  });
  if (emptyLinks > 0) {
    findings.push({ id: uuidv4(), title: `${emptyLinks} Link(s) With No Descriptive Text`, description: `${emptyLinks} link(s) have no visible text. Screen reader users hear "link" with no destination context.`, severity: 'medium', category: 'accessibility', location: '<a> elements', recommendation: 'Add descriptive text or aria-label to all links.' });
  }

  return findings;
}
