import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import type { Finding, LoadStats } from '../../client/src/types/scan';

const REQUESTS = 15;

export async function runLoadScan(
  url: string,
  onProgress: (p: number) => void
): Promise<{ findings: Finding[]; loadStats: LoadStats }> {
  const times: number[] = [];
  let errors = 0;

  for (let i = 0; i < REQUESTS; i++) {
    onProgress(10 + Math.round((i / REQUESTS) * 80));
    const start = Date.now();
    try {
      await axios.get(url, {
        timeout: 10000,
        validateStatus: () => true,
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; RibbyLoadTest/1.0)' }
      });
      times.push(Date.now() - start);
    } catch {
      errors++;
      times.push(10000);
    }
  }

  onProgress(95);

  const sorted = [...times].sort((a, b) => a - b);
  const avg = Math.round(times.reduce((a, b) => a + b, 0) / times.length);
  const min = sorted[0];
  const max = sorted[sorted.length - 1];
  const p95 = sorted[Math.floor(sorted.length * 0.95)] ?? max;
  const successRate = Math.round(((REQUESTS - errors) / REQUESTS) * 100);

  const findings: Finding[] = [];

  if (successRate < 95) {
    findings.push({
      id: uuidv4(), title: `High Error Rate: ${100 - successRate}% of Requests Failed`,
      description: `${errors} out of ${REQUESTS} requests failed or timed out. Users are experiencing intermittent failures.`,
      severity: successRate < 80 ? 'critical' : 'high',
      category: 'performance', location: url,
      recommendation: 'Investigate server logs for errors, check memory/CPU limits, and add auto-scaling.'
    });
  }

  if (avg > 3000) {
    findings.push({
      id: uuidv4(), title: 'Average Response Time Critical',
      description: `Average response across ${REQUESTS} requests: ${avg}ms. Sustained high latency will cause user drop-off.`,
      severity: 'critical', category: 'performance', location: 'Server Response',
      recommendation: 'Profile backend performance, add caching layers, and optimize database queries.'
    });
  } else if (avg > 1500) {
    findings.push({
      id: uuidv4(), title: 'Slow Average Response Time',
      description: `Average response across ${REQUESTS} requests: ${avg}ms. Target is under 800ms.`,
      severity: 'high', category: 'performance', location: 'Server Response',
      recommendation: 'Enable server-side caching, optimize queries, and consider a CDN.'
    });
  } else if (avg > 800) {
    findings.push({
      id: uuidv4(), title: 'Moderate Average Response Time',
      description: `Average response across ${REQUESTS} requests: ${avg}ms. Aim for under 800ms.`,
      severity: 'medium', category: 'performance', location: 'Server Response',
      recommendation: 'Review backend performance and add caching.'
    });
  }

  const variance = max - min;
  if (variance > 2000) {
    findings.push({
      id: uuidv4(), title: 'High Response Time Variance',
      description: `Response times ranged from ${min}ms to ${max}ms (${variance}ms variance). Inconsistent performance degrades user experience.`,
      severity: 'high', category: 'performance', location: 'Server Response',
      recommendation: 'Investigate what causes slow outliers — could be GC pauses, cold starts, or resource contention.'
    });
  }

  if (p95 > 2000) {
    findings.push({
      id: uuidv4(), title: `P95 Response Time: ${p95}ms`,
      description: `95% of requests took ${p95}ms or less. Users on the slow tail are experiencing significant delays.`,
      severity: p95 > 4000 ? 'high' : 'medium', category: 'performance', location: 'Server Response',
      recommendation: 'Optimize for the slow cases — check background jobs, memory pressure, and database lock contention.'
    });
  }

  if (findings.length === 0) {
    findings.push({
      id: uuidv4(), title: `Load Test Passed: ${REQUESTS} Requests Completed`,
      description: `All ${REQUESTS} requests succeeded with an average of ${avg}ms. The server handles repeated requests well.`,
      severity: 'info', category: 'performance', location: url,
      recommendation: 'Continue monitoring under real traffic conditions for sustained performance.'
    });
  }

  const loadStats: LoadStats = {
    requests: REQUESTS, successRate, avgTime: avg, minTime: min, maxTime: max, p95Time: p95, errors
  };

  return { findings, loadStats };
}
