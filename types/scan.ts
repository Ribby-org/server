export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Category = 'security' | 'performance' | 'functional' | 'accessibility';
export type ScanStatus = 'pending' | 'scanning' | 'complete' | 'error';
export type ScanType = 'security' | 'performance' | 'accessibility' | 'functional' | 'load' | 'seo' | 'ssl' | 'dns' | 'links' | 'crypto';

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: Category;
  location?: string;
  recommendation: string;
}

export interface ScanMeta {
  responseTime: number;
  statusCode: number;
  contentSize: number;
  server?: string;
  contentType?: string;
  isHttps: boolean;
  redirectCount: number;
  hostname?: string;
  ipAddress?: string;
  ipVersion?: 'ipv4' | 'ipv6';
  hostingProvider?: string;
  hostingCname?: string;
  detectedServices?: string[];
  headerSnapshot?: Record<string, string>;
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  score: number;
  total: number;
}

export interface LoadStats {
  requests: number;
  successRate: number;
  avgTime: number;
  minTime: number;
  maxTime: number;
  p95Time: number;
  errors: number;
}

export interface ScanResult {
  id: string;
  url: string;
  type: ScanType;
  status: ScanStatus;
  progress: number;
  startedAt: string;
  completedAt?: string;
  findings: Finding[];
  summary: ScanSummary;
  meta: ScanMeta;
  loadStats?: LoadStats;
  error?: string;
}
