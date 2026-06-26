import type { IncomingMessage, ServerResponse } from 'http';
import { runFullScan } from './scanners/index';
import { runRepoScan, type RepoScanResult } from './scanners/repo';
import type { ScanResult, ScanType } from './types/scan';

const scans = new Map<string, ScanResult>();
const repoScans = new Map<string, RepoScanResult>();

// Concurrency limits — prevent server overload under high traffic
const MAX_CONCURRENT_SCANS = 10;
const MAX_CONCURRENT_REPO_SCANS = 5;

function activeScans() {
  return Array.from(scans.values()).filter(s => s.status === 'scanning').length;
}
function activeRepoScans() {
  return Array.from(repoScans.values()).filter(s => s.status === 'scanning').length;
}

// Auto-cleanup completed scans older than 30 minutes to prevent memory growth
setInterval(() => {
  const cutoff = Date.now() - 30 * 60 * 1000;
  for (const [id, s] of scans.entries()) {
    if (s.status !== 'scanning' && new Date(s.startedAt).getTime() < cutoff) scans.delete(id);
  }
  for (const [id, s] of repoScans.entries()) {
    if (s.status !== 'scanning' && new Date(s.startedAt).getTime() < cutoff) repoScans.delete(id);
  }
}, 10 * 60 * 1000);

function send(res: ServerResponse, status: number, data: unknown) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(body);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk: Buffer) => { data += chunk.toString(); });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

export function createMiddleware() {
  return async (req: IncomingMessage, res: ServerResponse, next: () => void) => {
    const url = req.url || '';
    const method = req.method || 'GET';

    if (!url.startsWith('/api')) return next();

    try {
      // ── Web scan ──────────────────────────────────────────────
      if (method === 'POST' && url === '/api/scan/start') {
        const raw = await readBody(req);
        const { url: targetUrl, type = 'security' } = JSON.parse(raw) as { url: string; type: ScanType };
        if (!targetUrl) return send(res, 400, { error: 'URL required' });
        if (activeScans() >= MAX_CONCURRENT_SCANS) {
          return send(res, 429, { error: 'Scanner is busy. Please try again in a moment.' });
        }

        for (const [existingId, s] of scans.entries()) {
          if (s.url === targetUrl && s.type === type) scans.delete(existingId);
        }

        const id = `scan-${Date.now()}-${type}`;
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
        if (activeRepoScans() >= MAX_CONCURRENT_REPO_SCANS) {
          return send(res, 429, { error: 'Repo scanner is busy. Please try again in a moment.' });
        }

        const id = `repo-${Date.now()}`;
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

      // ── Analytics ingest (public — called from ribby-sdk in external apps) ──
      if (url === '/api/analytics/event') {
        // Allow cross-origin requests from any app using ribby-sdk
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

        if (method === 'OPTIONS') {
          res.writeHead(204);
          res.end();
          return;
        }

        if (method === 'POST') {
          try {
            const raw = await readBody(req);
            const event = JSON.parse(raw);

            const SUPABASE_URL = process.env.VITE_SUPABASE_URL;
            const SUPABASE_KEY = process.env.VITE_SUPABASE_PUBLISHABLE_KEY;

            if (!SUPABASE_URL || !SUPABASE_KEY) {
              return send(res, 503, { error: 'Analytics not configured' });
            }

            // Look up which org owns this origin domain
            const domainRes = await fetch(
              `${SUPABASE_URL}/rest/v1/analytics_sites?domain=eq.${encodeURIComponent(event.origin)}&select=id,site_key`,
              { headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` } }
            );
            const sites = await domainRes.json() as { id: string; site_key: string }[];
            if (!sites?.length) {
              // Domain not registered — still accept but mark as unregistered
              return send(res, 202, { accepted: true, registered: false });
            }

            const siteKey = sites[0].site_key;

            // Insert event
            await fetch(`${SUPABASE_URL}/rest/v1/analytics_events`, {
              method: 'POST',
              headers: {
                apikey: SUPABASE_KEY,
                Authorization: `Bearer ${SUPABASE_KEY}`,
                'Content-Type': 'application/json',
                Prefer: 'return=minimal'
              },
              body: JSON.stringify({
                site_key:   siteKey,
                type:       event.type,
                page_url:   event.url,
                referrer:   event.referrer  || null,
                device:     event.device    || null,
                browser:    event.browser   || null,
                session_id: event.sessionId || null,
                event_name: event.eventName || null,
                lcp:  event.lcp  || null,
                fid:  event.fid  || null,
                cls:  event.cls  || null,
                ttfb: event.ttfb || null,
                fcp:  event.fcp  || null,
              })
            });

            return send(res, 200, { ok: true });
          } catch {
            return send(res, 500, { error: 'Ingest failed' });
          }
        }
      }

      next();
    } catch (err) {
      send(res, 500, { error: (err as Error).message });
    }
  };
}
