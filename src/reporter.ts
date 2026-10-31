import {escapeTerminal, type Severity} from './analyzer';
import type {ScanResult} from './scanner';
export type OutputFormat = 'text' | 'json';
export function report(result: ScanResult, format: OutputFormat, threshold: Severity): string {
  if (format === 'json') return JSON.stringify({schemaVersion: 1, generatedAt: new Date().toISOString(), threshold, ...result}, null, 2);
  const {audit, outdated, warnings} = result;
  const lines = ['DepScanX — auditoria de dependências',
    'Projeto: ' + escapeTerminal(result.directory),
    'Pacotes afetados: ' + audit.counts.total + ' (critical=' + audit.counts.critical + ', high=' + audit.counts.high + ', moderate=' + audit.counts.moderate + ', low=' + audit.counts.low + ', info=' + audit.counts.info + ')',
    'Limite de falha: ' + threshold];
  for (const p of audit.packages) {
    const advice = p.via.length ? ' | ' + p.via.map(escapeTerminal).join('; ') : '';
    lines.push('[' + p.severity.toUpperCase() + '] ' + escapeTerminal(p.name) + ' | range=' + escapeTerminal(p.range) + ' | direct=' + p.isDirect + advice);
  }
  if (outdated !== null) {
    lines.push('Dependências desatualizadas: ' + outdated.length);
    for (const p of outdated) lines.push(escapeTerminal(p.name) + ': ' + escapeTerminal(p.current) + ' → ' + escapeTerminal(p.wanted) + ' → ' + escapeTerminal(p.latest));
  }
  for (const warning of warnings) lines.push('AVISO: ' + escapeTerminal(warning));
  return lines.join('\n');
}
