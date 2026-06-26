import { promises as dns } from 'dns';
import { v4 as uuidv4 } from 'uuid';
import type { Finding } from '../types/scan';

async function safeLookup<T>(fn: () => Promise<T>): Promise<T | null> {
  try { return await fn(); } catch { return null; }
}

function flattenTxt(records: string[][]): string[] {
  return records.map(r => r.join(''));
}

export async function runDnsScan(url: string, onProgress: (p: number) => void): Promise<Finding[]> {
  const findings: Finding[] = [];

  let domain = '';
  try { domain = new URL(url).hostname.replace(/^www\./, ''); } catch {
    findings.push({ id: uuidv4(), title: 'Invalid URL', description: 'Could not extract domain from URL.', severity: 'critical', category: 'functional', recommendation: 'Check the URL format.' });
    return findings;
  }

  onProgress(15);

  // 1. MX Records
  const mxRecords = await safeLookup(() => dns.resolveMx(domain));
  if (!mxRecords || mxRecords.length === 0) {
    findings.push({ id: uuidv4(), title: 'No MX Records Found', description: `Domain "${domain}" has no mail exchange records. Email delivery is not configured.`, severity: 'info', category: 'functional', location: `MX @ ${domain}`, recommendation: 'Add MX records if you plan to receive email on this domain.' });
  }

  onProgress(30);

  // 2. SPF Record
  const txtRecords = await safeLookup(() => dns.resolveTxt(domain));
  const txts = txtRecords ? flattenTxt(txtRecords) : [];
  const spf = txts.find(r => r.startsWith('v=spf1'));

  if (!spf) {
    findings.push({ id: uuidv4(), title: 'No SPF Record Found', description: 'Sender Policy Framework (SPF) record is missing. Anyone can send email claiming to be from your domain — a major phishing risk.', severity: 'critical', category: 'security', location: `TXT @ ${domain}`, recommendation: 'Add a TXT record at your DNS provider with the value matching your mail provider. Examples: Google Workspace → "v=spf1 include:_spf.google.com ~all" | Microsoft 365 → "v=spf1 include:spf.protection.outlook.com ~all" | No email sending → "v=spf1 -all". Contact your email provider for the correct include value.' });
  } else {
    if (spf.includes('+all')) {
      findings.push({ id: uuidv4(), title: 'SPF Record Uses Permissive +all', description: 'SPF is configured with "+all" which allows any server to send email as your domain. This defeats the purpose of SPF.', severity: 'critical', category: 'security', location: `TXT @ ${domain}`, recommendation: 'Replace "+all" with "~all" (soft fail) or "-all" (hard fail).' });
    } else if (!spf.includes('~all') && !spf.includes('-all')) {
      findings.push({ id: uuidv4(), title: 'SPF Record Missing Fail Policy', description: 'SPF record has no fail qualifier (~all or -all). Unauthorised senders are not explicitly rejected.', severity: 'medium', category: 'security', location: `TXT @ ${domain}`, recommendation: 'Add "~all" or "-all" at the end of your SPF record.' });
    } else {
      findings.push({ id: uuidv4(), title: 'SPF Record Configured', description: `SPF record found: ${spf}`, severity: 'info', category: 'security', location: `TXT @ ${domain}`, recommendation: 'SPF is configured. Periodically verify it covers all sending services.' });
    }
  }

  onProgress(50);

  // 3. DMARC Record
  const dmarcRecords = await safeLookup(() => dns.resolveTxt(`_dmarc.${domain}`));
  const dmarcs = dmarcRecords ? flattenTxt(dmarcRecords) : [];
  const dmarc = dmarcs.find(r => r.startsWith('v=DMARC1'));

  if (!dmarc) {
    findings.push({ id: uuidv4(), title: 'No DMARC Record Found', description: 'DMARC policy is missing. Without it, email receivers have no instructions on handling failed SPF/DKIM checks, enabling spoofing.', severity: 'critical', category: 'security', location: `TXT @ _dmarc.${domain}`, recommendation: `Add a TXT record named "_dmarc.${domain}" with value: "v=DMARC1; p=none; rua=mailto:dmarc-reports@${domain}". Start with p=none to monitor reports without blocking mail, then move to p=quarantine or p=reject once you confirm legitimate mail passes. Use a real inbox you control for the rua address.` });
  } else {
    const policyMatch = dmarc.match(/p=(none|quarantine|reject)/i);
    const policy = policyMatch?.[1]?.toLowerCase();
    if (policy === 'none') {
      findings.push({ id: uuidv4(), title: 'DMARC Policy Set to "none" (Monitor Only)', description: 'DMARC is in monitoring mode (p=none). Spoofed emails are not rejected or quarantined — only reported.', severity: 'high', category: 'security', location: `TXT @ _dmarc.${domain}`, recommendation: 'Upgrade DMARC policy to p=quarantine or p=reject after verifying legitimate email flow.' });
    } else {
      findings.push({ id: uuidv4(), title: `DMARC Configured (p=${policy})`, description: `DMARC policy is set to "${policy}". Spoofed emails will be ${policy === 'reject' ? 'rejected outright' : 'sent to spam'}.`, severity: 'info', category: 'security', location: `TXT @ _dmarc.${domain}`, recommendation: policy === 'quarantine' ? 'Consider upgrading to p=reject for maximum protection.' : 'DMARC is properly configured with reject policy.' });
    }
  }

  onProgress(70);

  // 4. DKIM (check common selectors)
  const dkimSelectors = ['default', 'google', 'mail', 'k1', 'dkim', 'selector1', 'selector2'];
  let dkimFound = false;
  for (const sel of dkimSelectors) {
    const rec = await safeLookup(() => dns.resolveTxt(`${sel}._domainkey.${domain}`));
    if (rec && flattenTxt(rec).some(r => r.includes('v=DKIM1'))) {
      dkimFound = true;
      findings.push({ id: uuidv4(), title: `DKIM Record Found (selector: ${sel})`, description: `DKIM record found at ${sel}._domainkey.${domain}. Outgoing emails are cryptographically signed.`, severity: 'info', category: 'security', location: `TXT @ ${sel}._domainkey.${domain}`, recommendation: 'DKIM is configured. Ensure all sending services have valid DKIM keys.' });
      break;
    }
  }

  if (!dkimFound) {
    findings.push({ id: uuidv4(), title: 'No DKIM Record Found', description: 'No DKIM signing record detected for common selectors. Outgoing emails cannot be cryptographically verified, increasing spam risk.', severity: 'high', category: 'security', location: `TXT @ *._domainkey.${domain}`, recommendation: 'Configure DKIM signing through your email provider (Google Workspace, SendGrid, etc.).' });
  }

  onProgress(85);

  // 5. CAA Records
  const caaRecords = await safeLookup(() => dns.resolveCaa(domain));
  if (!caaRecords || (Array.isArray(caaRecords) && caaRecords.length === 0)) {
    findings.push({ id: uuidv4(), title: 'No CAA Records Found', description: 'Certification Authority Authorization (CAA) records are missing. Any CA can issue SSL certificates for your domain, increasing risk of mis-issuance.', severity: 'medium', category: 'security', location: `CAA @ ${domain}`, recommendation: `Add a CAA record at your DNS provider. Example to allow only Let's Encrypt: type=CAA, name="${domain}", value='0 issue "letsencrypt.org"'. For DigiCert use "digicert.com". Only include CAs you actually use. Check your current SSL certificate issuer first.` });
  }

  onProgress(100);

  return findings;
}
