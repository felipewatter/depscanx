# Changelog

## 1.1.0 — 2026-10-31

- Scanner npm funcional via npm audit --json com limiar configurável.
- Relatório complementar de versões desatualizadas com npm outdated --json.
- CLI dep-scanx com formatos texto/JSON e códigos de saída 0/1/2.
- Validação de lockfile, timeout e limite de bytes na saída de comandos npm.
- Neutralização de caracteres de controle em relatórios de terminal.
- 15 testes automatizados e CI multiplataforma (Node 22/24; Linux, Windows e macOS).
- Documentação sobre limitações: detecção de pacotes abandonados não implementada.

## 1.0.0

- Estrutura inicial com rotinas demonstrativas sem auditoria efetiva.
