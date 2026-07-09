import type { IncomingMessage, ServerResponse } from 'http';
import { randomUUID } from 'crypto';
import { runFullScan, fetchSiteIntel } from './scanners/index';
import { runRepoScan, type RepoScanResult } from './scanners/repo';
import type { ScanResult, ScanType } from './types/scan';

const scans = new Map<string, ScanResult>();
const repoScans = new Map<string, RepoScanResult>();

// Concurrency limits — keep low to avoid RAM spikes on Railway free tier
const MAX_CONCURRENT_SCANS = 3;
const MAX_CONCURRENT_REPO_SCANS = 2;
const MAX_STORED_SCANS = 20;      // hard cap on in-memory scan results
const MAX_STORED_REPO_SCANS = 10;

// ── Security helpers ──────────────────────────────────────────────────────────

const MAX_BODY_BYTES = 64 * 1024; // 64 KB

// Block SSRF: private/loopback/link-local/cloud-metadata ranges
const BLOCKED_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^0\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,   // link-local / AWS metadata
  /^::1$/,
  /^fc00:/i,
  /^fe80:/i,
  /^0\.0\.0\.0$/,
];

function isSafeUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    const host = u.hostname.toLowerCase();
    return !BLOCKED_PATTERNS.some(p => p.test(host));
  } catch { return false; }
}

// Simple shared-secret auth — set RIBBY_API_SECRET on Railway and in client env
const API_SECRET = process.env.RIBBY_API_SECRET;

function isAuthorized(req: IncomingMessage): boolean {
  if (!API_SECRET) return true; // secret not configured → open (dev mode)
  const header = req.headers['x-ribby-secret'] as string | undefined;
  return header === API_SECRET;
}

function activeScans() {
  return Array.from(scans.values()).filter(s => s.status === 'scanning').length;
}
function activeRepoScans() {
  return Array.from(repoScans.values()).filter(s => s.status === 'scanning').length;
}

// Auto-cleanup: run every 3 minutes, evict scans older than 10 minutes
setInterval(() => {
  const cutoff = Date.now() - 10 * 60 * 1000;
  for (const [id, s] of scans.entries()) {
    if (s.status !== 'scanning' && new Date(s.startedAt).getTime() < cutoff) scans.delete(id);
  }
  for (const [id, s] of repoScans.entries()) {
    if (s.status !== 'scanning' && new Date(s.startedAt).getTime() < cutoff) repoScans.delete(id);
  }
  // Hard cap: if still over limit, evict oldest completed scans first
  if (scans.size > MAX_STORED_SCANS) {
    const sorted = Array.from(scans.entries())
      .filter(([, s]) => s.status !== 'scanning')
      .sort(([, a], [, b]) => new Date(a.startedAt).getTime() - new Date(b.startedAt).getTime());
    for (const [id] of sorted.slice(0, scans.size - MAX_STORED_SCANS)) scans.delete(id);
  }
  if (repoScans.size > MAX_STORED_REPO_SCANS) {
    const sorted = Array.from(repoScans.entries())
      .filter(([, s]) => s.status !== 'scanning')
      .sort(([, a], [, b]) => new Date(a.startedAt).getTime() - new Date(b.startedAt).getTime());
    for (const [id] of sorted.slice(0, repoScans.size - MAX_STORED_REPO_SCANS)) repoScans.delete(id);
  }
}, 3 * 60 * 1000);

function send(res: ServerResponse, status: number, data: unknown) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(body);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    let bytes = 0;
    req.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > MAX_BODY_BYTES) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      data += chunk.toString();
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

export function createMiddleware() {
  return async (req: IncomingMessage, res: ServerResponse, next: () => void) => {
    const url = req.url || '';
    const method = req.method || 'GET';

    if (!url.startsWith('/api')) return next();

    // ── Auth check (all /api routes) ─────────────────────────────
    if (!isAuthorized(req)) {
      return send(res, 401, { error: 'Unauthorized' });
    }

    try {
      // ── Site intel (lightweight prefetch) ─────────────────────
      if (method === 'POST' && url === '/api/site/intel') {
        const raw = await readBody(req);
        const { url: targetUrl } = JSON.parse(raw) as { url: string };
        if (!targetUrl) return send(res, 400, { error: 'URL required' });
        if (!isSafeUrl(targetUrl)) return send(res, 400, { error: 'URL not allowed' });

        try {
          const meta = await fetchSiteIntel(targetUrl);
          return send(res, 200, meta);
        } catch {
          return send(res, 502, { error: 'Failed to fetch site intel' });
        }
      }

      // ── Web scan ──────────────────────────────────────────────
      if (method === 'POST' && url === '/api/scan/start') {
        const raw = await readBody(req);
        const { url: targetUrl, type = 'security' } = JSON.parse(raw) as { url: string; type: ScanType };
        if (!targetUrl) return send(res, 400, { error: 'URL required' });
        if (!isSafeUrl(targetUrl)) return send(res, 400, { error: 'URL not allowed' });
        if (activeScans() >= MAX_CONCURRENT_SCANS) {
          return send(res, 429, { error: 'Scanner is busy. Please try again in a moment.' });
        }

        for (const [existingId, s] of scans.entries()) {
          if (s.url === targetUrl && s.type === type) scans.delete(existingId);
        }

        const id = `scan-${randomUUID()}`;
        const placeholder: ScanResult = {
          id, url: targetUrl, type, status: 'scanning', progress: 5,
          startedAt: new Date().toISOString(), findings: [],
          summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, score: 0, total: 0 },
          meta: { responseTime: 0, statusCode: 0, contentSize: 0, isHttps: false, redirectCount: 0 }
        };
        scans.set(id, placeholder);

        runFullScan(targetUrl, type, (progress) => {
          const s = scans.get(id);
          if (s) s.progress = progress;
        }).then(result => {
          const s = scans.get(id);
          if (s) Object.assign(s, result, { id });
        }).catch(err => {
          const s = scans.get(id);
          if (s) { s.status = 'error'; s.error = (err as Error).message; }
        });

        return send(res, 200, { id });
      }

      if (method === 'GET' && url === '/api/scans') {
        const all = Array.from(scans.values())
          .filter(s => s.status === 'complete')
          .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
        return send(res, 200, all);
      }

      const scanIdMatch = url.match(/^\/api\/scan\/([^/?]+)/);
      if (scanIdMatch) {
        if (method === 'GET') {
          const scan = scans.get(scanIdMatch[1]);
          if (!scan) return send(res, 404, { error: 'Not found' });
          return send(res, 200, scan);
        }
        if (method === 'DELETE') {
          scans.delete(scanIdMatch[1]);
          return send(res, 200, { success: true });
        }
      }

      // ── Repo scan ─────────────────────────────────────────────
      if (method === 'POST' && url === '/api/repo-scan/start') {
        const raw = await readBody(req);
        const { repoUrl, githubToken } = JSON.parse(raw) as { repoUrl: string; githubToken?: string };
        if (!repoUrl) return send(res, 400, { error: 'repoUrl required' });
        if (!isSafeUrl(repoUrl)) return send(res, 400, { error: 'URL not allowed' });
        if (activeRepoScans() >= MAX_CONCURRENT_REPO_SCANS) {
          return send(res, 429, { error: 'Repo scanner is busy. Please try again in a moment.' });
        }

        const id = `repo-${randomUUID()}`;
        const placeholder: RepoScanResult = {
          id, repoUrl, owner: '', repo: '', defaultBranch: '',
          status: 'scanning', progress: 5,
          startedAt: new Date().toISOString(), findings: [],
          summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0, score: 0 },
          meta: { filesScanned: 0, depsChecked: 0, language: [] }
        };
        repoScans.set(id, placeholder);

        runRepoScan(repoUrl, (progress) => {
          const s = repoScans.get(id);
          if (s) s.progress = progress;
        }, githubToken).then(result => {
          const s = repoScans.get(id);
          if (s) Object.assign(s, result, { id });
        }).catch(err => {
          const s = repoScans.get(id);
          if (s) { s.status = 'error'; s.error = (err as Error).message; }
        });

        return send(res, 200, { id });
      }

      const repoIdMatch = url.match(/^\/api\/repo-scan\/([^/?]+)/);
      if (repoIdMatch) {
        if (method === 'GET') {
          const scan = repoScans.get(repoIdMatch[1]);
          if (!scan) return send(res, 404, { error: 'Not found' });
          return send(res, 200, scan);
        }
        if (method === 'DELETE') {
          repoScans.delete(repoIdMatch[1]);
          return send(res, 200, { success: true });
        }
      }

      next();
    } catch (err) {
      const isDev = process.env.NODE_ENV !== 'production';
      send(res, 500, { error: isDev ? (err as Error).message : 'Internal server error' });
    }
  };
}
