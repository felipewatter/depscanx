/** Invokes npm without shell interpolation on Unix; no scripts or installation. */
import {spawn} from 'node:child_process';
import {lstat, readFile} from 'node:fs/promises';
import {resolve, join} from 'node:path';
import {parseAudit, parseOutdated, type AuditReport, type OutdatedIssue} from './analyzer';

export type ProcessResult = {code: number | null; stdout: string; stderr: string};
export type NpmRunner = (args: readonly string[], cwd: string, timeoutMs: number) => Promise<ProcessResult>;
export type ScanResult = {directory: string; audit: AuditReport; outdated: OutdatedIssue[] | null; warnings: string[]};

export const runNpm: NpmRunner = (args, cwd, timeoutMs) => new Promise((resolveRun, reject) => {
  // Arguments are chosen internally and contain no caller-controlled strings.
  const isWindows = process.platform === 'win32';
  const command = isWindows ? 'npm.cmd' : 'npm';
  const proc = spawn(command, [...args], {cwd, shell: isWindows, windowsHide: true, env: {...process.env, CI: 'true', npm_config_yes: 'false'}});
  const limit = 8 * 1024 * 1024;
  let stdout = '', stderr = '', total = 0, ended = false;
  const timer = setTimeout(() => {
    if (!ended) {proc.kill(); reject(new Error('npm excedeu o tempo limite')); ended = true;}
  }, timeoutMs);
  const collect = (field: 'stdout'|'stderr', data: Buffer) => {
    total += data.length;
    if (total > limit) {
      if (!ended) {proc.kill(); reject(new Error('Saída npm excedeu 8 MiB')); ended = true;}
      return;
    }
    if (field === 'stdout') stdout += data.toString('utf8'); else stderr += data.toString('utf8');
  };
  proc.stdout.on('data', (data: Buffer) => collect('stdout', data));
  proc.stderr.on('data', (data: Buffer) => collect('stderr', data));
  proc.once('error', error => {clearTimeout(timer); if (!ended) {ended = true; reject(error);}});
  proc.once('close', code => {clearTimeout(timer); if (!ended) {ended = true; resolveRun({code, stdout, stderr});}});
});

async function regularFile(path: string): Promise<boolean> {
  try {return (await lstat(path)).isFile();} catch {return false;}
}
export async function validateProject(input: string): Promise<string> {
  const directory = resolve(input);
  if (!(await lstat(directory).catch(() => null))?.isDirectory()) throw new Error('Diretório do projeto inexistente');
  if (!(await regularFile(join(directory, 'package.json')))) throw new Error('package.json ausente ou não é arquivo regular');
  if (!(await regularFile(join(directory, 'package-lock.json'))) && !(await regularFile(join(directory, 'npm-shrinkwrap.json')))) {
    throw new Error('package-lock.json ou npm-shrinkwrap.json é obrigatório para npm audit (gere com npm install --package-lock-only)');
  }
  const pkg = JSON.parse(await readFile(join(directory, 'package.json'), 'utf8')) as unknown;
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) throw new Error('package.json inválido');
  return directory;
}
export async function scanProject(input: string, options: {outdated: boolean; timeoutMs: number}, runner: NpmRunner = runNpm): Promise<ScanResult> {
  const directory = await validateProject(input);
  const auditResult = await runner(['audit', '--json', '--ignore-scripts', '--no-fund'], directory, options.timeoutMs);
  // npm audit returns 1 when vulnerabilities are found (expected). Errors return other codes/invalid payload.
  if (auditResult.code !== 0 && auditResult.code !== 1) throw new Error(`npm audit falhou (código ${String(auditResult.code)}): ${auditResult.stderr.slice(0,300)}`);
  const audit = parseAudit(auditResult.stdout);
  let outdated: OutdatedIssue[] | null = null;
  const warnings: string[] = [];
  if (options.outdated) {
    try {
      const result = await runner(['outdated', '--json'], directory, options.timeoutMs);
      if (result.code !== 0 && result.code !== 1) throw new Error(`código ${String(result.code)}`);
      outdated = parseOutdated(result.stdout);
    } catch (error) {warnings.push('Consulta de versões desatualizadas indisponível: ' + (error instanceof Error ? error.message : 'erro desconhecido'));}
  }
  return {directory, audit, outdated, warnings};
}
