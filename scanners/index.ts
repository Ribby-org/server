import axios, { AxiosResponse } from 'axios';
import { v4 as uuidv4 } from 'uuid';
import dns from 'node:dns/promises';
import { runSecurityScan } from './security';
import { runPerformanceScan } from './performance';
import { runAccessibilityScan } from './accessibility';
import { runFunctionalScan } from './functional';
import { runLoadScan } from './load';
import { runSeoScan } from './seo';
import { runSslScan } from './ssl';
import { runDnsScan } from './dns';
import { runBrokenLinksScan } from './links';
import { runCryptoScan } from './crypto';
import type { Finding, ScanMeta, ScanResult, ScanSummary, ScanType } from '../types/scan';

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SNAPSHOT_HEADERS = [
  'server',
  'x-powered-by',
  'via',
  'x-cache',
  'cf-ray',
  'x-vercel-id',
  'x-vercel-cache',
  'x-railway-edge',
  'x-railway-request-id',
  'x-render-origin-server',
  'x-render-routing',
  'x-clerk-auth-status',
  'x-clerk-auth-reason',
  'x-amz-cf-id',
  'x-request-id',
  'content-type',
  'date'
];

function detectHostingProvider(headers: Record<string, string>): string | undefined {
  const blob = `${Object.keys(headers).join(' ')} ${Object.values(headers).join(' ')}`.toLowerCase();
  if (blob.includes('railway')) return 'Railway';
  if (blob.includes('vercel')) return 'Vercel';
  if (blob.includes('cloudflare') || blob.includes('cf-ray')) return 'Cloudflare';
  if (blob.includes('netlify')) return 'Netlify';
  if (blob.includes('render')) return 'Render';
  if (blob.includes('fly.io') || blob.includes('fly-')) return 'Fly.io';
  if (blob.includes('heroku')) return 'Heroku';
  if (blob.includes('amazon') || blob.includes('aws')) return 'AWS';
  if (blob.includes('gcp') || blob.includes('google')) return 'Google Cloud';
  if (blob.includes('azure')) return 'Azure';
  return undefined;
}

function detectServicesFromHeaders(headers: Record<string, string>): string[] {
  const services = new Set<string>();
  const keys = Object.keys(headers).map(k => k.toLowerCase());
  const blob = `${keys.join(' ')} ${Object.values(headers).join(' ')}`.toLowerCase();

  // Auth / edge / platform signals
  if (keys.some(k => k.startsWith('x-clerk-')) || blob.includes('clerk')) services.add('Clerk');
  if (keys.includes('cf-ray') || blob.includes('cloudflare')) services.add('Cloudflare');
  if (keys.includes('x-vercel-id') || blob.includes('vercel')) services.add('Vercel');
  if (keys.some(k => k.startsWith('x-railway-')) || blob.includes('railway')) services.add('Railway');
  if (blob.includes('render')) services.add('Render');
  if (blob.includes('netlify')) services.add('Netlify');
  if (blob.includes('fly.io') || blob.includes('fly-')) services.add('Fly.io');
  if (blob.includes('heroku')) services.add('Heroku');
  if (keys.includes('x-amz-cf-id') || blob.includes('cloudfront')) services.add('AWS CloudFront');

  return Array.from(services);
}

async function resolveCname(hostname: string): Promise<string | undefined> {
  try {
    const cnames = await dns.resolveCname(hostname);
    return cnames?.[0];
  } catch {
    return undefined;
  }
}

function detectHostingFromCname(cname?: string): string | undefined {
  if (!cname) return undefined;
  const c = cname.toLowerCase();
  if (c.includes('vercel-dns.com') || c.includes('.vercel.app')) return 'Vercel';
  if (c.includes('onrender.com') || c.includes('render.com')) return 'Render';
  if (c.includes('netlify.app') || c.includes('netlify.com')) return 'Netlify';
  if (c.includes('railway.app') || c.includes('railway') || c.includes('railway.internal')) return 'Railway';
  if (c.includes('fly.dev') || c.includes('fly.io')) return 'Fly.io';
  if (c.includes('herokuapp.com') || c.includes('heroku')) return 'Heroku';
  if (c.includes('cloudfront.net')) return 'AWS CloudFront';
  if (c.includes('fastly.net')) return 'Fastly';
  if (c.includes('cdn.cloudflare.net') || c.includes('cloudflare')) return 'Cloudflare';
  return undefined;
}

async function resolveHost(hostname: string): Promise<{ ipAddress?: string; ipVersion?: 'ipv4' | 'ipv6' }> {
  try {
    const ipv4 = await dns.resolve4(hostname);
    if (ipv4.length > 0) return { ipAddress: ipv4[0], ipVersion: 'ipv4' };
  } catch {}
  try {
    const ipv6 = await dns.resolve6(hostname);
    if (ipv6.length > 0) return { ipAddress: ipv6[0], ipVersion: 'ipv6' };
  } catch {}
  try {
    const resolved = await dns.lookup(hostname);
    if (resolved?.address) {
      return { ipAddress: resolved.address, ipVersion: resolved.family === 6 ? 'ipv6' : 'ipv4' };
    }
  } catch {}
  return {};
}

function buildHeaderSnapshot(headers: Record<string, string>): Record<string, string> {
  const snapshot: Record<string, string> = {};
  for (const h of SNAPSHOT_HEADERS) {
    if (headers[h]) snapshot[h] = headers[h];
  }
  return snapshot;
}

function buildSummary(findings: Finding[]): ScanSummary {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  const penalty = counts.critical * 25 + counts.high * 10 + counts.medium * 5 + counts.low * 2 + counts.info * 0.5;
  return { ...counts, score: Math.max(0, Math.min(100, Math.round(100 - penalty))), total: findings.length };
}

async function fetchPage(url: string, onProgress: (p: number) => void) {
  onProgress(10);
  let redirectCount = 0;
  const start = Date.now();

  const res: AxiosResponse = await axios.get(url, {
    timeout: 15000, maxRedirects: 10,
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; RibbyScanner/1.0)', 'Accept': 'text/html,*/*;q=0.8' },
    validateStatus: () => true,
    beforeRedirect: () => { redirectCount++; }
  });

  const responseTime = Date.now() - start;
  const html = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(res.headers)) {
    headers[k.toLowerCase()] = Array.isArray(v) ? v[0] : String(v);
  }
  const contentSize = Buffer.byteLength(html, 'utf8');
  const finalUrl = String((res.request as { res?: { responseUrl?: string } } | undefined)?.res?.responseUrl || url);
  const hostname = new URL(finalUrl).hostname;
  const host = await resolveHost(hostname);
  const hostingCname = await resolveCname(hostname);
  const fromCname = detectHostingFromCname(hostingCname);
  const fromHeaders = detectHostingProvider(headers);
  const hostingProvider = fromCname || fromHeaders;
  const detectedServices = detectServicesFromHeaders(headers);
  if (fromCname) detectedServices.push(fromCname);
  const headerSnapshot = buildHeaderSnapshot(headers);
  return { res, html, headers, responseTime, contentSize, redirectCount, hostname, ...host, hostingProvider, hostingCname, detectedServices: Array.from(new Set(detectedServices)), headerSnapshot };
}

export async function runFullScan(url: string, type: ScanType, onProgress: (p: number) => void): Promise<ScanResult> {
  const id = uuidv4();
  const startedAt = new Date().toISOString();

  let normalized = url.trim();
  if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
    normalized = 'https://' + normalized;
  }

  try {
    let findings: Finding[] = [];
    let meta: ScanMeta = { responseTime: 0, statusCode: 200, contentSize: 0, isHttps: normalized.startsWith('https://'), redirectCount: 0 };
    let loadStats;

    if (type === 'load') {
      const result = await runLoadScan(normalized, onProgress);
      findings = result.findings;
      loadStats = result.loadStats;
      meta.responseTime = loadStats.avgTime;

    } else if (type === 'ssl') {
      onProgress(10);
      const { headers } = await fetchPage(normalized, () => {}).catch(() => ({ headers: {} as Record<string, string> }));
      onProgress(40);
      findings = await runSslScan(normalized, headers);
      onProgress(100);

    } else if (type === 'dns') {
      findings = await runDnsScan(normalized, onProgress);

    } else {
      // All types that need the HTML page
      const { res, html, headers, responseTime, contentSize, redirectCount, hostname, ipAddress, ipVersion, hostingProvider, hostingCname, detectedServices, headerSnapshot } = await fetchPage(normalized, onProgress);
      onProgress(40);
      meta = {
        responseTime,
        statusCode: res.status,
        contentSize,
        server: headers['server'] || headers['x-powered-by'],
        contentType: headers['content-type'],
        isHttps: normalized.startsWith('https://'),
        redirectCount,
        hostname,
        ipAddress,
        ipVersion,
        hostingProvider,
        hostingCname,
        detectedServices,
        headerSnapshot
      };

      if (type === 'security')      findings = runSecurityScan(normalized, html, headers);
      else if (type === 'performance')   findings = runPerformanceScan(html, headers, responseTime, contentSize);
      else if (type === 'accessibility') findings = runAccessibilityScan(html);
      else if (type === 'functional')    findings = runFunctionalScan(normalized, html, headers, res.status, redirectCount);
      else if (type === 'seo')           findings = await runSeoScan(normalized, html, headers);
      else if (type === 'links')         findings = await runBrokenLinksScan(normalized, html, onProgress);
      else if (type === 'crypto')        findings = runCryptoScan(normalized, html, headers);

      onProgress(100);
    }

    findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);

    return { id, url: normalized, type, status: 'complete', progress: 100, startedAt, completedAt: new Date().toISOString(), findings, summary: buildSummary(findings), meta, ...(loadStats ? { loadStats } : {}) };

  } catch (err: unknown) {
    return {
      id, url: normalized, type, status: 'error', progress: 100, startedAt,
      completedAt: new Date().toISOString(), findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, score: 0, total: 0 },
      meta: { responseTime: 0, statusCode: 0, contentSize: 0, isHttps: false, redirectCount: 0 },
      error: 'Failed to reach the URL. It may be unreachable, require authentication, or have blocked scanner requests.'
    };
  }
}
