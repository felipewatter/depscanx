#!/usr/bin/env node
import {resolve} from 'node:path';
import {SEVERITIES, shouldFail, type Severity} from './analyzer';
import {report, type OutputFormat} from './reporter';
import {scanProject} from './scanner';

const HELP = `DepScanX — scanner de dependências npm

Uso: dep-scanx [--path DIRETORIO] [--format text|json] [--fail-on info|low|moderate|high|critical] [--skip-outdated] [--timeout SEGUNDOS]

  --path           Diretório com package.json e package-lock.json (padrão: .)
  --format         text (padrão) ou json (saída estruturada)
  --fail-on        Severidade mínima para exit 1 (padrão: high)
  --skip-outdated  Não chama npm outdated (mais rápido e com menos consultas)
  --timeout        Timeout de cada comando npm: 5 a 300 segundos (padrão: 60)
  --help           Exibe esta mensagem
  --version        Exibe a versão

Códigos: 0=aprovado, 1=vulnerabilidades acima do limite, 2=erro operacional.
Requer npm e lockfile. npm audit e npm outdated acessam o registro configurado pelo npm.
`;
export type CliOptions = {path: string; format: OutputFormat; failOn: Severity; skipOutdated: boolean; timeoutMs: number};
export function parseArgs(args: readonly string[]): CliOptions | 'help' | 'version' {
  const options: CliOptions = {path: '.', format: 'text', failOn: 'high', skipOutdated: false, timeoutMs: 60000};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--help' || a === '-h') return 'help';
    if (a === '--version' || a === '-v') return 'version';
    if (a === '--skip-outdated') {options.skipOutdated = true; continue;}
    if (!['--path', '--format', '--fail-on', '--timeout'].includes(a ?? '')) throw new Error('Argumento não reconhecido: ' + a);
    const value = args[++i];
    if (!value || value.startsWith('--')) throw new Error('Valor ausente para ' + a);
    if (a === '--path') options.path = value;
    if (a === '--format') {
      if (value !== 'text' && value !== 'json') throw new Error('Formato inválido: ' + value);
      options.format = value;
    }
    if (a === '--fail-on') {
      if (!SEVERITIES.includes(value as Severity)) throw new Error('Severidade inválida: ' + value);
      options.failOn = value as Severity;
    }
    if (a === '--timeout') {
      if (!/^[1-9]\d*$/.test(value)) throw new Error('Timeout inválido');
      const seconds = Number(value);
      if (!Number.isSafeInteger(seconds) || seconds < 5 || seconds > 300) throw new Error('Timeout deve ficar entre 5 e 300 segundos');
      options.timeoutMs = seconds * 1000;
    }
  }
  return options;
}
export async function main(args = process.argv.slice(2)): Promise<number> {
  let options: ReturnType<typeof parseArgs>;
  try {options = parseArgs(args);} catch (error) {
    console.error('DepScanX: ' + (error instanceof Error ? error.message : 'argumentos inválidos'));
    return 2;
  }
  if (options === 'help') {console.log(HELP); return 0;}
  if (options === 'version') {console.log('1.1.0'); return 0;}
  try {
    const result = await scanProject(resolve(options.path), {outdated: !options.skipOutdated, timeoutMs: options.timeoutMs});
    console.log(report(result, options.format, options.failOn));
    return shouldFail(result.audit, options.failOn) ? 1 : 0;
  } catch (error) {
    console.error('DepScanX: ' + (error instanceof Error ? error.message : 'erro desconhecido'));
    return 2;
  }
}
if (require.main === module) void main().then(code => {process.exitCode = code;});
