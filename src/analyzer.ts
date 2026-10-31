/** Normalizes npm audit/outdated JSON without trusting it as executable content. */
export const SEVERITIES = ['info', 'low', 'moderate', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];
export type AuditIssue = {
  name: string;
  severity: Severity;
  isDirect: boolean;
  range: string;
  via: string[];
  fixAvailable: boolean | { name: string; version: string; isSemVerMajor: boolean };
};
export type OutdatedIssue = {
  name: string;
  current: string;
  wanted: string;
  latest: string;
  type: string;
};
export type AuditReport = { packages: AuditIssue[]; counts: Record<Severity | 'total', number> };
const isRecord = (x: unknown): x is Record<string, unknown> => x !== null && typeof x === 'object' && !Array.isArray(x);
const safeString = (x: unknown, max = 300): string => typeof x === 'string' ? x.slice(0, max) : '';
const emptyCounts = (): AuditReport['counts'] => ({info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0});
function severity(x: unknown): Severity { return SEVERITIES.includes(x as Severity) ? x as Severity : 'info'; }

export function parseAudit(raw: string): AuditReport {
  let obj: unknown;
  try { obj = JSON.parse(raw); } catch { throw new Error('Saída npm audit não é um JSON válido'); }
  if (!isRecord(obj) || isRecord(obj.error) || !isRecord(obj.vulnerabilities)) {
    const err = isRecord(obj) && isRecord(obj.error) ? safeString(obj.error.summary) : '';
    throw new Error('npm audit não forneceu um relatório de vulnerabilidades válido' + (err ? ': ' + err : ''));
  }
  const packages: AuditIssue[] = [];
  for (const [name, value] of Object.entries(obj.vulnerabilities)) {
    if (!isRecord(value)) continue;
    const via: string[] = [];
    if (Array.isArray(value.via)) {
      for (const item of value.via) {
        if (typeof item === 'string') via.push(safeString(item));
        else if (isRecord(item)) via.push(safeString(item.title) || safeString(item.name) || 'Advisory sem título');
      }
    }
    const fix = value.fixAvailable;
    const fixAvailable = isRecord(fix)
      ? {name: safeString(fix.name), version: safeString(fix.version), isSemVerMajor: fix.isSemVerMajor === true}
      : fix === true;
    packages.push({name: safeString(name, 200), severity: severity(value.severity), isDirect: value.isDirect === true,
      range: safeString(value.range), via: via.slice(0, 20), fixAvailable});
  }
  packages.sort((a,b) => SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity) || a.name.localeCompare(b.name));
  const counts = emptyCounts();
  for (const issue of packages) counts[issue.severity]++;
  counts.total = packages.length;
  // Counts are affected-package counts, not independent CVE/advisory counts.
  return {packages, counts};
}

export function parseOutdated(raw: string): OutdatedIssue[] {
  if (!raw.trim()) return [];
  let obj: unknown;
  try { obj = JSON.parse(raw); } catch { throw new Error('Saída npm outdated não é um JSON válido'); }
  if (!isRecord(obj) || isRecord(obj.error)) throw new Error('npm outdated retornou formato inesperado');
  return Object.entries(obj).filter(([, item]) => isRecord(item)).map(([name,item]) => {
    const x = item as Record<string, unknown>;
    return {name: safeString(name, 200), current: safeString(x.current) || 'não instalado',
      wanted: safeString(x.wanted), latest: safeString(x.latest), type: safeString(x.type)};
  }).sort((a,b) => a.name.localeCompare(b.name));
}

export function shouldFail(report: AuditReport, threshold: Severity): boolean {
  const limit = SEVERITIES.indexOf(threshold);
  return report.packages.some(p => SEVERITIES.indexOf(p.severity) >= limit);
}

export function escapeTerminal(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f\u001b]/g, '?');
}
