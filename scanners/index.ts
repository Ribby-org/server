import axios, { AxiosResponse } from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { runSecurityScan } from './security';
import { runPerformanceScan } from './performance';
import { runAccessibilityScan } from './accessibility';
import { runFunctionalScan } from './functional';
import { runLoadScan } from './load';
import { runSeoScan } from './seo';
import { runSslScan } from './ssl';
import { runDnsScan } from './dns';
import { runBrokenLinksScan } from './links';
import type { Finding, ScanMeta, ScanResult, ScanSummary, ScanType } from '../types/scan';

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

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
  return { res, html, headers, responseTime, contentSize, redirectCount };
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
      const { res, html, headers, responseTime, contentSize, redirectCount } = await fetchPage(normalized, onProgress);
      onProgress(40);
      meta = { responseTime, statusCode: res.status, contentSize, server: headers['server'] || headers['x-powered-by'], contentType: headers['content-type'], isHttps: normalized.startsWith('https://'), redirectCount };

      if (type === 'security')      findings = runSecurityScan(normalized, html, headers);
      else if (type === 'performance')   findings = runPerformanceScan(html, headers, responseTime, contentSize);
      else if (type === 'accessibility') findings = runAccessibilityScan(html);
      else if (type === 'functional')    findings = runFunctionalScan(normalized, html, headers, res.status, redirectCount);
      else if (type === 'seo')           findings = await runSeoScan(normalized, html, headers);
      else if (type === 'links')         findings = await runBrokenLinksScan(normalized, html, onProgress);

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
      error: (err as Error).message || 'Failed to reach the URL'
    };
  }
}
