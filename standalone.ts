/**
 * Standalone Express server for Ribby scanner API.
 * Deploy this to Railway, Render, or any Node.js host.
 * The Vercel frontend calls this for all scanning features.
 */
import http from 'http';
import { createMiddleware } from './middleware';

const PORT = process.env.PORT || 3001;

const middleware = createMiddleware();

const server = http.createServer((req, res) => {
  const origin = req.headers.origin || '';
  const isAnalytics = req.url === '/api/analytics/event';

  // Analytics ingest is public — allow any origin
  if (isAnalytics) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else {
    const allowed = [
      'https://ribby-client.vercel.app',
      'http://localhost:5173',
      'http://localhost:3000',
    ];
    if (allowed.includes(origin) || origin.endsWith('.vercel.app')) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  middleware(req, res, () => {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });
});

server.listen(PORT, () => {
  console.log(`Ribby scanner API running on port ${PORT}`);
});
