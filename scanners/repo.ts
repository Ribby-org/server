import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';

export interface RepoFinding {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: 'secret' | 'dependency' | 'exposure' | 'config';
  file?: string;
  line?: number;
  cve?: string;
  fixVersion?: string;
  recommendation: string;
}

export interface RepoScanResult {
  id: string;
  repoUrl: string;
  owner: string;
  repo: string;
  defaultBranch: string;
  status: 'scanning' | 'complete' | 'error';
  progress: number;
  startedAt: string;
  completedAt?: string;
  findings: RepoFinding[];
  summary: { critical: number; high: number; medium: number; low: number; info: number; total: number; score: number };
  meta: { filesScanned: number; depsChecked: number; language: string[] };
  error?: string;
}

const GH = 'https://api.github.com';
const OSV = 'https://api.osv.dev/v1/querybatch';

function ghHeaders(token?: string) {
  return {
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'RibbyScanner/1.0',
    ...(token ? { Authorization: `Bearer ${token}` } : {})
  };
}

const SECRET_PATTERNS: { name: string; pattern: RegExp; severity: RepoFinding['severity'] }[] = [
  { name: 'AWS Access Key ID',        pattern: /AKIA[0-9A-Z]{16}/g,                                            severity: 'critical' },
  { name: 'AWS Secret Access Key',    pattern: /aws.{0,20}secret.{0,20}[=:]["']?[0-9a-zA-Z\/+]{40}/gi,        severity: 'critical' },
  { name: 'GitHub Personal Token',    pattern: /ghp_[a-zA-Z0-9]{36}/g,                                         severity: 'critical' },
  { name: 'GitHub OAuth Token',       pattern: /gho_[a-zA-Z0-9]{36}/g,                                         severity: 'critical' },
  { name: 'Stripe Live Secret Key',   pattern: /sk_live_[0-9a-zA-Z]{24,}/g,                                    severity: 'critical' },
  { name: 'Stripe Live Public Key',   pattern: /pk_live_[0-9a-zA-Z]{24,}/g,                                    severity: 'high' },
  { name: 'Private Key Block',        pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,           severity: 'critical' },
  { name: 'Database Connection URL',  pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"'`]{10,}/gi,         severity: 'critical' },
  { name: 'Slack Bot Token',          pattern: /xox[baprs]-[0-9a-zA-Z\-]{10,}/g,                              severity: 'critical' },
  { name: 'SendGrid API Key',         pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,                   severity: 'high' },
  { name: 'Twilio Account SID',       pattern: /AC[a-z0-9]{32}/g,                                              severity: 'high' },
  { name: 'Generic Hardcoded Password', pattern: /password\s*[=:]\s*["'][^"']{8,}["']/gi,                      severity: 'high' },
  { name: 'Generic API Key',          pattern: /api[_-]?key\s*[=:]\s*["'][a-zA-Z0-9_\-]{20,}["']/gi,          severity: 'high' },
  { name: 'Hardcoded Secret',         pattern: /secret\s*[=:]\s*["'][a-zA-Z0-9_\-!@#$%^&*]{10,}["']/gi,       severity: 'high' },
  { name: 'Firebase Database URL',    pattern: /https:\/\/[a-z0-9-]+\.firebaseio\.com/gi,                      severity: 'medium' },
  // Crypto-specific secrets
  { name: 'Crypto Wallet Private Key', pattern: /(?:private[_-]?key|secret[_-]?key|pkey|prv)\s*[=:]\s*["']?(?:0x)?[0-9a-fA-F]{64}["']?/gi, severity: 'critical' },
  { name: 'Mnemonic Seed Phrase',      pattern: /(?:['"`]|^[A-Z0-9_]*MNEMONIC[A-Z0-9_]*\s*=\s*)((?:[a-z]{3,8}[ \t]+){11,23}[a-z]{3,8})(?:['"`]|$)/gm, severity: 'critical' },
  { name: 'Hardcoded IV/Nonce',        pattern: /(?:iv|nonce|salt)\s*[=:]\s*["'][0-9a-fA-F]{16,}["']/gi,      severity: 'high' },
  { name: 'Hardcoded AES Key',         pattern: /(?:aes|cipher)[_-]?key\s*[=:]\s*["'][0-9a-fA-F]{32,}["']/gi, severity: 'critical' },
  { name: 'JWT Secret Hardcoded',      pattern: /jwt[_-]?secret\s*[=:]\s*["'][^"']{8,}["']/gi,                severity: 'critical' },
];

const SENSITIVE_FILES = [
  { path: '.env',                     severity: 'critical' as const, desc: 'Environment variables file committed to repo' },
  { path: '.env.local',              severity: 'critical' as const, desc: 'Local env variables committed to repo' },
  { path: '.env.production',         severity: 'critical' as const, desc: 'Production env variables committed to repo' },
  { path: '.env.development',        severity: 'critical' as const, desc: 'Development env variables committed to repo' },
  { path: 'config/database.yml',     severity: 'critical' as const, desc: 'Database credentials configuration' },
  { path: 'config/secrets.yml',      severity: 'critical' as const, desc: 'Rails secrets file' },
  { path: '.aws/credentials',        severity: 'critical' as const, desc: 'AWS credentials file' },
  { path: 'id_rsa',                  severity: 'critical' as const, desc: 'SSH private key' },
  { path: 'server.key',              severity: 'critical' as const, desc: 'SSL/TLS private key' },
  { path: '.npmrc',                   severity: 'high' as const,     desc: 'NPM config (may contain auth tokens)' },
  { path: '.pypirc',                  severity: 'high' as const,     desc: 'PyPI config (may contain auth tokens)' },
  { path: 'wp-config.php',           severity: 'high' as const,     desc: 'WordPress config (may contain DB credentials)' },
  { path: 'web.config',              severity: 'medium' as const,   desc: 'IIS web config (may expose server info)' },
  { path: '.htpasswd',               severity: 'high' as const,     desc: 'Apache password file' },
];

function decodeBase64(encoded: string): string {
  try { return Buffer.from(encoded, 'base64').toString('utf-8'); } catch { return ''; }
}

interface FileResult {
  content: string | null;
  exists: boolean | null; // true if exists, false if 404, null if API error/rate limit
}

async function getFileContent(
  owner: string,
  repo: string,
  path: string,
  branch?: string,
  token?: string
): Promise<FileResult> {
  try {
    const url = `${GH}/repos/${owner}/${repo}/contents/${path}${branch ? `?ref=${branch}` : ''}`;
    const { data } = await axios.get(url, { headers: ghHeaders(token), timeout: 8000 });
    return {
      content: data.content ? decodeBase64(data.content) : '',
      exists: true
    };
  } catch (err: any) {
    if (err?.response?.status === 404) {
      return { content: null, exists: false };
    }
    return { content: null, exists: null };
  }
}

async function fileExists(
  owner: string,
  repo: string,
  path: string,
  branch?: string,
  token?: string
): Promise<boolean> {
  try {
    const url = `${GH}/repos/${owner}/${repo}/contents/${path}${branch ? `?ref=${branch}` : ''}`;
    await axios.get(url, { headers: ghHeaders(token), timeout: 8000 });
    return true;
  } catch {
    return false;
  }
}

function scanForSecrets(content: string, filePath: string): RepoFinding[] {
  const findings: RepoFinding[] = [];
  const lines = content.split('\n');

  for (const { name, pattern, severity } of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    const match = pattern.exec(content);
    if (match) {
      const lineNum = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: uuidv4(), title: `${name} Detected`,
        description: `A potential ${name} was found hardcoded in the source code. This credential may be compromised if the repository is or was ever public.`,
        severity, category: 'secret', file: filePath, line: lineNum,
        recommendation: `Remove the credential from the code immediately. Rotate/revoke the exposed credential. Use environment variables instead.`
      });
    }
  }

  // Check for weak crypto algorithms
  const weakCrypto = [
    { pattern: /createHash\s*\(\s*['"]md5['"]\s*\)/gi,      label: 'MD5 hashing',         fix: 'Use SHA-256 or bcrypt instead of MD5.' },
    { pattern: /createHash\s*\(\s*['"]sha1['"]\s*\)/gi,     label: 'SHA-1 hashing',        fix: 'Use SHA-256 or better. SHA-1 is broken.' },
    { pattern: /createCipheriv\s*\(\s*['"]des/gi,           label: 'DES encryption',       fix: 'Replace DES with AES-256-GCM.' },
    { pattern: /createCipheriv\s*\(\s*['"]rc4/gi,           label: 'RC4 cipher',           fix: 'Replace RC4 with AES-256-GCM.' },
    { pattern: /createCipheriv\s*\(\s*['"]aes-\d+-ecb/gi,   label: 'AES-ECB mode',         fix: 'Use AES-GCM or AES-CBC with a random IV.' },
    { pattern: /Math\.random\s*\(\)/g,                      label: 'Math.random() usage',  fix: 'Use crypto.randomBytes() for security-sensitive randomness.' },
  ];
  for (const { pattern, label, fix } of weakCrypto) {
    pattern.lastIndex = 0;
    const match = pattern.exec(content);
    if (match) {
      const lineNum = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: uuidv4(),
        title: `Weak Cryptography: ${label}`,
        description: `Insecure cryptographic operation (${label}) detected in ${filePath} at line ${lineNum}.`,
        severity: 'high',
        category: 'secret',
        file: filePath,
        line: lineNum,
        recommendation: fix
      });
    }
  }

  // Check for TODO/FIXME with security notes
  lines.forEach((line, i) => {
    if (/TODO.*(?:security|auth|password|secret|key|token)/i.test(line) || /FIXME.*(?:security|auth|password)/i.test(line)) {
      findings.push({
        id: uuidv4(), title: 'Unresolved Security TODO',
        description: `Line ${i + 1} in ${filePath} has an unresolved security-related TODO/FIXME: "${line.trim().substring(0, 100)}"`,
        severity: 'low', category: 'config', file: filePath, line: i + 1,
        recommendation: 'Resolve all security-related TODO comments before deploying to production.'
      });
    }
  });

  return findings;
}

async function checkDependencies(owner: string, repo: string, branch?: string, token?: string): Promise<{ findings: RepoFinding[]; count: number; langs: string[] }> {
  const findings: RepoFinding[] = [];
  let count = 0;
  const langs: string[] = [];

  // npm (Node.js)
  const pkgJsonResult = await getFileContent(owner, repo, 'package.json', branch, token);
  if (pkgJsonResult.content) {
    langs.push('Node.js');
    try {
      const pkg = JSON.parse(pkgJsonResult.content);
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      const queries = Object.entries(allDeps).map(([name, version]) => ({
        package: { name, ecosystem: 'npm' },
        version: String(version).replace(/[\^~>=<]/g, '').split(' ')[0]
      }));
      count += queries.length;

      if (queries.length > 0) {
        try {
          const { data } = await axios.post(OSV, { queries }, { timeout: 10000 });
          data.results?.forEach((result: any, i: number) => {
            if (result.vulns?.length > 0) {
              const dep = queries[i];
              const vuln = result.vulns[0];
              const severity = vuln.database_specific?.severity === 'CRITICAL' ? 'critical' :
                               vuln.database_specific?.severity === 'HIGH' ? 'high' :
                               vuln.database_specific?.severity === 'MODERATE' ? 'medium' : 'low';
              const fixVersion = vuln.affected?.[0]?.ranges?.[0]?.events?.find((e: any) => e.fixed)?.fixed;
              findings.push({
                id: uuidv4(),
                title: `Vulnerable Dependency: ${dep.package.name}@${dep.version}`,
                description: `${vuln.summary || 'Known vulnerability detected'}. CVE: ${vuln.aliases?.find((a: string) => a.startsWith('CVE')) || vuln.id}`,
                severity, category: 'dependency',
                file: 'package.json', cve: vuln.aliases?.find((a: string) => a.startsWith('CVE')) || vuln.id,
                fixVersion,
                recommendation: fixVersion
                  ? `Upgrade ${dep.package.name} to v${fixVersion} or later.`
                  : `Review and update ${dep.package.name}. Check npm advisories for patches.`
              });
            }
          });
        } catch { /* OSV API may fail — skip */ }
      }
    } catch { /* invalid package.json */ }
  }

  // Python
  const requirementsResult = await getFileContent(owner, repo, 'requirements.txt', branch, token);
  if (requirementsResult.content) {
    langs.push('Python');
    const deps = requirementsResult.content.split('\n')
      .filter(l => l.trim() && !l.startsWith('#'))
      .map(l => { const [name, version] = l.split('=='); return { name: name.trim(), version: (version || '').trim() }; })
      .filter(d => d.version);
    count += deps.length;

    if (deps.length > 0) {
      try {
        const queries = deps.map(d => ({ package: { name: d.name, ecosystem: 'PyPI' }, version: d.version }));
        const { data } = await axios.post(OSV, { queries }, { timeout: 10000 });
        data.results?.forEach((result: any, i: number) => {
          if (result.vulns?.length > 0) {
            const dep = deps[i];
            const vuln = result.vulns[0];
            findings.push({
              id: uuidv4(),
              title: `Vulnerable Python Package: ${dep.name}==${dep.version}`,
              description: `${vuln.summary || 'Known vulnerability'}. ${vuln.aliases?.find((a: string) => a.startsWith('CVE')) || vuln.id}`,
              severity: 'high', category: 'dependency', file: 'requirements.txt',
              cve: vuln.aliases?.find((a: string) => a.startsWith('CVE')),
              recommendation: `Update ${dep.name} to a patched version.`
            });
          }
        });
      } catch { /* skip */ }
    }
  }

  return { findings, count, langs };
}

function buildSummary(findings: RepoFinding[]) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  const penalty = counts.critical * 25 + counts.high * 10 + counts.medium * 5 + counts.low * 2;
  return { ...counts, total: findings.length, score: Math.max(0, Math.min(100, 100 - penalty)) };
}

async function getRepoTree(owner: string, repo: string, branch: string, token?: string): Promise<string[]> {
  try {
    const { data } = await axios.get(`${GH}/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`, {
      headers: ghHeaders(token),
      timeout: 10000
    });
    if (!Array.isArray(data.tree)) return [];

    const EXCLUDED_DIRS = [
      /^(node_modules|dist|build|\.git|public|assets|vendor|images|tests|__tests__|coverage|\.next|\.nuxt)\//i
    ];
    
    const ALLOWED_EXTENSIONS = /\.(js|jsx|ts|tsx|py|go|rb|php|java|env|yml|yaml|json|conf|ini)$/i;
    const EXCLUDED_FILES = /^(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Cargo\.lock|Gemfile\.lock)$/i;

    const files: string[] = [];
    for (const item of data.tree) {
      if (item.type !== 'blob') continue;
      const path = item.path as string;
      const isExcludedDir = EXCLUDED_DIRS.some(regex => regex.test(path));
      if (isExcludedDir) continue;
      const filename = path.split('/').pop() || '';
      if (EXCLUDED_FILES.test(filename)) continue;
      if (ALLOWED_EXTENSIONS.test(path)) {
        files.push(path);
      }
    }
    return files;
  } catch {
    return [];
  }
}

export async function runRepoScan(repoUrl: string, onProgress: (p: number) => void, githubToken?: string): Promise<RepoScanResult> {
  const id = uuidv4();
  const startedAt = new Date().toISOString();

  // Parse GitHub URL
  const match = repoUrl.match(/github\.com\/([^/]+)\/([^/\s?#]+)/);
  if (!match) {
    return {
      id, repoUrl, owner: '', repo: '', defaultBranch: '', status: 'error',
      progress: 100, startedAt, findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0, score: 0 },
      meta: { filesScanned: 0, depsChecked: 0, language: [] },
      error: 'Invalid GitHub URL. Use format: https://github.com/owner/repo'
    };
  }

  const [, owner, repo] = match;
  onProgress(5);

  // Get repo info
  let defaultBranch = 'main';
  try {
    const { data } = await axios.get(`${GH}/repos/${owner}/${repo}`, { headers: ghHeaders(githubToken), timeout: 8000 });
    defaultBranch = data.default_branch || 'main';
  } catch (err: any) {
    const status = err?.response?.status;
    return {
      id, repoUrl, owner, repo, defaultBranch, status: 'error',
      progress: 100, startedAt, findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0, score: 0 },
      meta: { filesScanned: 0, depsChecked: 0, language: [] },
      error: status === 404 ? 'Repository not found or is private.' : status === 403 ? 'GitHub API rate limit reached. Try again later.' : 'Could not access repository.'
    };
  }

  onProgress(15);
  const allFindings: RepoFinding[] = [];
  let filesScanned = 0;

  // 1. Check for sensitive files
  for (const { path, severity, desc } of SENSITIVE_FILES) {
    if (await fileExists(owner, repo, path, defaultBranch, githubToken)) {
      allFindings.push({
        id: uuidv4(), title: `Sensitive File Exposed: ${path}`,
        description: `"${path}" exists in the repository. ${desc}. This file likely contains credentials or secrets.`,
        severity, category: 'exposure', file: path,
        recommendation: `Remove "${path}" from the repository immediately. Add it to .gitignore. Rotate any credentials it may have contained.`
      });
      filesScanned++;
    }
  }

  onProgress(30);

  // 2. Check .gitignore for missing patterns
  const gitignoreResult = await getFileContent(owner, repo, '.gitignore', defaultBranch, githubToken);
  if (gitignoreResult.exists === false) {
    allFindings.push({
      id: uuidv4(), title: 'No .gitignore File Found',
      description: 'Repository has no .gitignore file. Sensitive files like .env, node_modules, and credentials may be accidentally committed.',
      severity: 'medium', category: 'config',
      recommendation: 'Add a .gitignore file. GitHub provides templates at github.com/github/gitignore for most languages and frameworks. At minimum exclude: .env, node_modules/, *.key, *.pem.'
    });
  } else if (gitignoreResult.exists === true && gitignoreResult.content) {
    filesScanned++;
    const gitignoreContent = gitignoreResult.content;
    if (!gitignoreContent.includes('.env')) {
      allFindings.push({
        id: uuidv4(), title: '.env Not in .gitignore',
        description: 'Your .gitignore does not include .env files. Environment files with secrets could be accidentally committed.',
        severity: 'high', category: 'config', file: '.gitignore',
        recommendation: 'Add ".env" and ".env.*" to your .gitignore file.'
      });
    }
  }

  onProgress(45);

  // 3. Dependency vulnerability check
  const { findings: depFindings, count: depsChecked, langs } = await checkDependencies(owner, repo, defaultBranch, githubToken);
  allFindings.push(...depFindings);

  onProgress(65);

  // 4. Scan files recursively for secrets
  const repoFiles = await getRepoTree(owner, repo, defaultBranch, githubToken);
  const filesToScan = repoFiles.slice(0, 50); // scan up to 50 key files to avoid timeouts/rate limit

  for (let i = 0; i < filesToScan.length; i++) {
    const file = filesToScan[i];
    const fileResult = await getFileContent(owner, repo, file, defaultBranch, githubToken);
    if (fileResult.content) {
      filesScanned++;
      const secrets = scanForSecrets(fileResult.content, file);
      allFindings.push(...secrets);
    }
    onProgress(Math.min(90, 65 + ((i + 1) / filesToScan.length) * 25));
  }

  // 5. Check for security policy
  const hasSecurityMd = await fileExists(owner, repo, 'SECURITY.md', defaultBranch, githubToken);
  if (!hasSecurityMd) {
    allFindings.push({
      id: uuidv4(), title: 'No Security Policy (SECURITY.md)',
      description: 'Repository has no SECURITY.md. Responsible disclosure and vulnerability reporting is not documented.',
      severity: 'info', category: 'config',
      recommendation: 'Add a SECURITY.md to explain how to report security vulnerabilities. GitHub has a template for this.'
    });
  }

  onProgress(100);

  // Sort by severity
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  allFindings.sort((a, b) => order[a.severity] - order[b.severity]);

  return {
    id, repoUrl, owner, repo, defaultBranch, status: 'complete',
    progress: 100, startedAt, completedAt: new Date().toISOString(),
    findings: allFindings, summary: buildSummary(allFindings),
    meta: { filesScanned, depsChecked, language: langs }
  };
}
