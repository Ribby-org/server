import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import type { RepoFinding } from './repo';

export interface NpmScanResult {
  id: string;
  packageName: string;
  version: string;
  description: string;
  homepage?: string;
  githubRepo?: string;
  license?: string;
  dependenciesCount: number;
  status: 'scanning' | 'complete' | 'error';
  findings: RepoFinding[];
  summary: { critical: number; high: number; medium: number; low: number; info: number; total: number; score: number };
  error?: string;
}

const REGISTRY = 'https://registry.npmjs.org';
const OSV = 'https://api.osv.dev/v1/query';

function cleanGithubUrl(url: string): string | undefined {
  if (!url) return undefined;
  // Convert git+https://github.com/user/repo.git or git://github.com/user/repo to https://github.com/user/repo
  const match = url.match(/github\.com\/([^/]+)\/([^/.]+)/);
  if (match) {
    return `https://github.com/${match[1]}/${match[2]}`;
  }
  return undefined;
}

export async function runNpmScan(rawPackageName: string): Promise<NpmScanResult> {
  const id = `npm-${uuidv4()}`;
  
  // Clean package name (remove npm: prefix, spaces, etc.)
  let packageName = rawPackageName.replace(/^npm:/i, '').trim();
  
  // Handle package name from npmjs.com URL
  // e.g., https://www.npmjs.com/package/lodash or https://www.npmjs.com/package/@types/node
  const urlMatch = packageName.match(/npmjs\.com\/package\/(@?[a-zA-Z0-9_.-]+Rank(?:\/[a-zA-Z0-9_.-]+)?)/i) || 
                   packageName.match(/npmjs\.com\/package\/(@?[a-zA-Z0-9_.-]+(?:\/[a-zA-Z0-9_.-]+)?)/i);
  if (urlMatch) {
    packageName = urlMatch[1];
  }

  // URL encode name for request (especially for scoped packages like @types/node)
  const encodedName = packageName.includes('/') 
    ? `@${encodeURIComponent(packageName.split('/')[0].replace('@', ''))}%2f${encodeURIComponent(packageName.split('/')[1])}`
    : encodeURIComponent(packageName);

  try {
    // 1. Fetch package metadata from npm registry
    const { data: registryData } = await axios.get(`${REGISTRY}/${encodedName}`, { timeout: 8000 });
    const latestVersion = registryData['dist-tags']?.latest || '0.0.0';
    const versionData = registryData.versions?.[latestVersion] || {};
    
    const description = registryData.description || 'No description provided.';
    const homepage = registryData.homepage || versionData.homepage;
    const license = registryData.license || versionData.license;
    const dependenciesCount = Object.keys(versionData.dependencies || {}).length;

    // Detect GitHub repo from repository field
    let repoUrl = registryData.repository?.url || versionData.repository?.url || '';
    if (typeof registryData.repository === 'string') repoUrl = registryData.repository;
    const githubRepo = cleanGithubUrl(repoUrl);

    // 2. Query OSV for package vulnerabilities
    const findings: RepoFinding[] = [];
    try {
      const { data: osvData } = await axios.post(OSV, {
        package: { name: packageName, ecosystem: 'npm' },
        version: latestVersion
      }, { timeout: 8000 });

      if (osvData.vulns && Array.isArray(osvData.vulns)) {
        osvData.vulns.forEach((vuln: any) => {
          const severity = vuln.database_specific?.severity === 'CRITICAL' ? 'critical' :
                           vuln.database_specific?.severity === 'HIGH' ? 'high' :
                           vuln.database_specific?.severity === 'MODERATE' ? 'medium' : 'low';
          const fixVersion = vuln.affected?.[0]?.ranges?.[0]?.events?.find((e: any) => e.fixed)?.fixed;
          const cve = vuln.aliases?.find((a: string) => a.startsWith('CVE')) || vuln.id;

          findings.push({
            id: uuidv4(),
            title: `Vulnerability: ${vuln.summary || 'Security advisory'}`,
            description: vuln.details || 'Known vulnerability in package source.',
            severity,
            category: 'dependency',
            cve,
            fixVersion,
            recommendation: fixVersion 
              ? `Upgrade ${packageName} to v${fixVersion} or later to patch this vulnerability.`
              : `Review advisory ${cve} for possible workarounds.`
          });
        });
      }
    } catch {
      // OSV query failed, proceed with registry metadata
    }

    // 3. Build summary counts
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => counts[f.severity]++);
    const penalty = counts.critical * 25 + counts.high * 10 + counts.medium * 5 + counts.low * 2;
    const score = Math.max(0, Math.min(100, 100 - penalty));

    return {
      id,
      packageName,
      version: latestVersion,
      description,
      homepage,
      githubRepo,
      license,
      dependenciesCount,
      status: 'complete',
      findings,
      summary: { ...counts, total: findings.length, score }
    };
  } catch (err: any) {
    return {
      id,
      packageName,
      version: 'unknown',
      description: '',
      dependenciesCount: 0,
      status: 'error',
      findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0, score: 0 },
      error: err?.response?.status === 404 
        ? `NPM package "${packageName}" not found in registry.` 
        : 'Failed to retrieve package information from NPM registry.'
    };
  }
}
