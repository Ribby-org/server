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
  weeklyDownloads?: number;
  maintainerCount?: number;
  daysSinceUpdate?: number;
  status: 'scanning' | 'complete' | 'error';
  findings: RepoFinding[];
  summary: { critical: number; high: number; medium: number; low: number; info: number; total: number; score: number };
  error?: string;
}

const REGISTRY = 'https://registry.npmjs.org';
const OSV      = 'https://api.osv.dev/v1/query';

function cleanGithubUrl(url: string): string | undefined {
  if (!url) return undefined;
  const match = url.match(/github\.com\/([^/]+)\/([^/.]+)/);
  return match ? `https://github.com/${match[1]}/${match[2]}` : undefined;
}

// ─── Heuristic: is this name suspiciously similar to a popular package? ──────
// Simple edit-distance (Levenshtein) to catch typosquatters like "lodahs" → "lodash"
const POPULAR = [
  'lodash','react','axios','express','moment','webpack','babel-core','typescript',
  'eslint','prettier','jest','mocha','chalk','commander','yargs','dotenv',
  'uuid','nodemon','cors','body-parser','jsonwebtoken','bcrypt','mongoose',
  'sequelize','socket.io','next','vue','angular','svelte','vite','rollup',
  'esbuild','turbo','prisma','stripe','twilio','aws-sdk','firebase',
];

function levenshtein(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[a.length][b.length];
}

function closestPopular(name: string): string | null {
  const bare = name.replace(/^@[^/]+\//, '').toLowerCase();
  for (const p of POPULAR) {
    const dist = levenshtein(bare, p);
    // Allow 1-char diff for short names, 2-char diff for longer ones
    const threshold = p.length <= 5 ? 1 : 2;
    if (dist > 0 && dist <= threshold) return p;
  }
  return null;
}

// ─── Check if scripts contain postinstall / preinstall hooks ─────────────────
function analyzeScripts(scripts: Record<string,string> = {}): string[] {
  const suspicious: string[] = [];
  const hooks = ['preinstall','postinstall','install','preuninstall','postuninstall'];
  for (const hook of hooks) {
    if (scripts[hook]) {
      suspicious.push(`"${hook}" hook: ${scripts[hook].slice(0, 120)}`);
    }
  }
  return suspicious;
}

// ─── Detect common exfiltration / scam patterns in script commands ───────────
const SCAM_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /curl\s+.*(http|ftp)/i,           label: 'curl to remote URL in install script' },
  { re: /wget\s+.*(http|ftp)/i,           label: 'wget to remote URL in install script' },
  { re: /exec\s*\(.*eval/i,               label: 'eval inside exec() in install script' },
  { re: /process\.env/i,                  label: 'access to process.env in install script' },
  { re: /fs\.(readFile|writeFile|unlink)/i,label: 'filesystem access in install script' },
  { re: /child_process/i,                 label: 'spawning child process from install script' },
  { re: /base64/i,                        label: 'base64 encoding/decoding in install script' },
  { re: /atob|btoa/i,                     label: 'base64 decode in install script' },
  { re: /require\s*\(\s*['"]http/i,       label: 'dynamic HTTP require in install script' },
  { re: /npm\s+publish|npm\s+token/i,     label: 'npm credential reference in install script' },
];

function analyzeScriptContent(scripts: Record<string,string> = {}): string[] {
  const hits: string[] = [];
  for (const [, cmd] of Object.entries(scripts)) {
    for (const { re, label } of SCAM_PATTERNS) {
      if (re.test(cmd) && !hits.includes(label)) hits.push(label);
    }
  }
  return hits;
}

export async function runNpmScan(rawPackageName: string): Promise<NpmScanResult> {
  const id = `npm-${uuidv4()}`;

  // Clean package name
  let packageName = rawPackageName.replace(/^npm:/i, '').trim();
  const urlMatch = packageName.match(/npmjs\.com\/package\/(@?[a-zA-Z0-9_.-]+(?:\/[a-zA-Z0-9_.-]+)?)/i);
  if (urlMatch) packageName = urlMatch[1];

  const encodedName = packageName.includes('/')
    ? `@${encodeURIComponent(packageName.split('/')[0].replace('@', ''))}%2f${encodeURIComponent(packageName.split('/')[1])}`
    : encodeURIComponent(packageName);

  try {
    // ── 1. Registry metadata ─────────────────────────────────────────────────
    const [registryRes, downloadsRes] = await Promise.allSettled([
      axios.get(`${REGISTRY}/${encodedName}`, { timeout: 10000 }),
      axios.get(`https://api.npmjs.org/downloads/point/last-week/${encodedName}`, { timeout: 6000 }),
    ]);

    if (registryRes.status === 'rejected') throw registryRes.reason;
    const reg = (registryRes as PromiseFulfilledResult<any>).value.data;

    const latestVersion = reg['dist-tags']?.latest || '0.0.0';
    const versionData   = reg.versions?.[latestVersion] || {};
    const description   = reg.description || versionData.description || '';
    const homepage      = reg.homepage   || versionData.homepage;
    const license       = reg.license    || versionData.license || 'UNKNOWN';
    const dependenciesCount = Object.keys(versionData.dependencies || {}).length;
    const scripts: Record<string,string> = versionData.scripts || {};
    const maintainers: any[]  = reg.maintainers || [];
    const weeklyDownloads: number | undefined =
      downloadsRes.status === 'fulfilled' ? (downloadsRes as PromiseFulfilledResult<any>).value.data?.downloads : undefined;

    let repoUrl = reg.repository?.url || versionData.repository?.url || '';
    if (typeof reg.repository === 'string') repoUrl = reg.repository;
    const githubRepo = cleanGithubUrl(repoUrl);

    // Days since last publish
    const lastPublished = reg.time?.[latestVersion];
    const daysSinceUpdate = lastPublished
      ? Math.floor((Date.now() - new Date(lastPublished).getTime()) / 86_400_000)
      : undefined;

    // ── 2. OSV vulnerability lookup ──────────────────────────────────────────
    const findings: RepoFinding[] = [];

    try {
      const { data: osvData } = await axios.post(OSV, {
        package: { name: packageName, ecosystem: 'npm' },
        version: latestVersion
      }, { timeout: 8000 });

      if (osvData.vulns && Array.isArray(osvData.vulns)) {
        osvData.vulns.forEach((vuln: any) => {
          const rawSev = vuln.database_specific?.severity || vuln.severity?.[0]?.score || '';
          const severity = /CRITICAL/i.test(rawSev) ? 'critical'
                         : /HIGH/i.test(rawSev)     ? 'high'
                         : /MODERATE|MEDIUM/i.test(rawSev) ? 'medium' : 'low';
          const fixVersion = vuln.affected?.[0]?.ranges?.[0]?.events
            ?.find((e: any) => e.fixed)?.fixed;
          const cve = vuln.aliases?.find((a: string) => a.startsWith('CVE')) || vuln.id;

          findings.push({
            id: uuidv4(),
            title: `CVE: ${vuln.summary || 'Security advisory'}`,
            description: vuln.details || 'Known vulnerability — check the advisory for details.',
            severity,
            category: 'dependency',
            cve,
            fixVersion,
            recommendation: fixVersion
              ? `Upgrade ${packageName} to v${fixVersion} or later.`
              : `Review advisory ${cve} and consider replacing this package.`,
          });
        });
      }
    } catch { /* OSV timeout — skip */ }

    // ── 3. Supply-chain / scam checks ────────────────────────────────────────

    // 3a. Typosquatting detection
    const similar = closestPopular(packageName);
    if (similar) {
      findings.push({
        id: uuidv4(),
        title: `Possible Typosquatting: resembles "${similar}"`,
        description: `The package name "${packageName}" is very similar to the popular package "${similar}". This is a common technique used by attackers to trick developers into installing malicious packages by mistake.`,
        severity: 'high',
        category: 'secret',
        recommendation: `Verify this is the correct package. If you meant "${similar}", uninstall this immediately and install the correct one.`,
      });
    }

    // 3b. Postinstall / install hooks (common vector for malware)
    const hooks = analyzeScripts(scripts);
    if (hooks.length > 0) {
      findings.push({
        id: uuidv4(),
        title: `Install Script Detected (${hooks.length} hook${hooks.length > 1 ? 's' : ''})`,
        description: `This package runs code automatically when installed:\n${hooks.map(h => `• ${h}`).join('\n')}\n\nPostinstall hooks are a common malware delivery vector — they can exfiltrate environment variables, SSH keys, or download additional payloads.`,
        severity: hooks.some(h => /postinstall|preinstall/.test(h)) ? 'high' : 'medium',
        category: 'secret',
        recommendation: `Review the script content carefully before installing. Audit node_modules/${packageName}/package.json. Consider using --ignore-scripts flag.`,
      });
    }

    // 3c. Suspicious content in install scripts (curl, eval, base64, etc.)
    const scamHits = analyzeScriptContent(scripts);
    if (scamHits.length > 0) {
      findings.push({
        id: uuidv4(),
        title: `Suspicious Code in Install Script (${scamHits.length} pattern${scamHits.length > 1 ? 's' : ''})`,
        description: `The package install scripts contain patterns associated with malware and data exfiltration:\n${scamHits.map(h => `• ${h}`).join('\n')}`,
        severity: 'critical',
        category: 'secret',
        recommendation: `Do NOT install this package. Report it at https://www.npmjs.com/support if you believe it is malicious.`,
      });
    }

    // 3d. No source repository linked
    if (!githubRepo && !homepage) {
      findings.push({
        id: uuidv4(),
        title: 'No Source Repository Linked',
        description: 'This package does not link to any public source repository. Legitimate packages almost always link to GitHub or a similar platform so the community can audit the code.',
        severity: 'medium',
        category: 'config',
        recommendation: 'Manually verify the package source before use. Search npm for the author and check their other packages.',
      });
    }

    // 3e. Unknown / missing license
    if (!license || license === 'UNKNOWN') {
      findings.push({
        id: uuidv4(),
        title: 'No License Specified',
        description: 'The package does not declare a software license. This creates legal uncertainty for projects that use it commercially, and can sometimes indicate an amateur or untrusted package.',
        severity: 'low',
        category: 'config',
        recommendation: 'Check the package README for any license information. Avoid using unlicensed packages in production.',
      });
    }

    // 3f. Abandoned package (no update in >2 years)
    if (daysSinceUpdate !== undefined && daysSinceUpdate > 730) {
      findings.push({
        id: uuidv4(),
        title: `Abandoned Package (Last updated ${Math.floor(daysSinceUpdate / 365)} year${daysSinceUpdate > 1095 ? 's' : ''} ago)`,
        description: `This package has not been updated in over ${Math.floor(daysSinceUpdate / 365)} year(s). Unmaintained packages may contain unpatched security vulnerabilities and may be incompatible with modern Node.js versions.`,
        severity: daysSinceUpdate > 1460 ? 'high' : 'medium',
        category: 'config',
        recommendation: 'Look for an actively maintained fork or alternative package. Check if the GitHub repo has open security issues.',
      });
    }

    // 3g. Very low download count (suspicious for anything claiming to be popular)
    if (weeklyDownloads !== undefined && weeklyDownloads < 50 && !packageName.startsWith('@')) {
      findings.push({
        id: uuidv4(),
        title: `Low Weekly Downloads (${weeklyDownloads.toLocaleString()} downloads/week)`,
        description: 'This package has very few weekly downloads. While this alone is not a problem (many niche packages are legitimate), combined with other signals it may indicate an untested, experimental, or potentially malicious package.',
        severity: 'info',
        category: 'config',
        recommendation: 'Verify the package author, check the README, and review the source code before using in production.',
      });
    }

    // 3h. Single maintainer with very high download count (account hijack risk)
    if (maintainers.length === 1 && weeklyDownloads !== undefined && weeklyDownloads > 100_000) {
      findings.push({
        id: uuidv4(),
        title: 'High-Value Single-Maintainer Package (Account Hijack Risk)',
        description: `This popular package (${weeklyDownloads.toLocaleString()} downloads/week) is controlled by a single npm account. If that account is compromised, a malicious version could be pushed to all users instantly.`,
        severity: 'medium',
        category: 'config',
        recommendation: 'Pin to an exact version in package.json (e.g. "1.2.3" not "^1.2.3") and use a lockfile. Enable npm audit in your CI pipeline.',
      });
    }

    // ── 4. Score ─────────────────────────────────────────────────────────────
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => { if (f.severity in counts) counts[f.severity as keyof typeof counts]++; });
    const penalty = counts.critical * 30 + counts.high * 15 + counts.medium * 7 + counts.low * 3 + counts.info;
    const score = Math.max(0, Math.min(100, 100 - penalty));

    return {
      id, packageName, version: latestVersion, description,
      homepage, githubRepo, license, dependenciesCount,
      weeklyDownloads, maintainerCount: maintainers.length, daysSinceUpdate,
      status: 'complete', findings,
      summary: { ...counts, total: findings.length, score },
    };

  } catch (err: any) {
    return {
      id, packageName, version: 'unknown', description: '',
      dependenciesCount: 0, status: 'error', findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0, score: 0 },
      error: err?.response?.status === 404
        ? `Package "${packageName}" not found on npm.`
        : `Failed to fetch package data: ${err?.message || 'unknown error'}`,
    };
  }
}
