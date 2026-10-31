# DepScanX — Dependency Security Scanner

[![CI](https://github.com/felipewatter/depscanx/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/depscanx/actions/workflows/ci.yml)

CLI de auditoria de dependências **Node.js/npm**, em TypeScript. Integra **npm audit** para verificar pacotes afetados por avisos de segurança conhecidos e **npm outdated** para identificar versões desatualizadas. Não instala dependências do projeto-alvo nem aplica correções automaticamente.

## Requisitos e instalação

Node.js 22 ou 24, npm 10+, e um projeto-alvo com package.json e package-lock.json ou npm-shrinkwrap.json.

    git clone https://github.com/felipewatter/depscanx.git
    cd depscanx
    npm install
    npm run build
    node bin/cli.js --help

Instalação global opcional a partir do checkout (executar depois do build):

    npm install -g .

## Exemplos de uso

    dep-scanx --path ./meu-projeto
    dep-scanx --path ./meu-projeto --format json --fail-on critical
    dep-scanx --path ./meu-projeto --skip-outdated
    dep-scanx --path ./meu-projeto --timeout 90

| Argumento | Padrão | Função |
|---|---|---|
| --path DIR | . | Diretório com manifest e lockfile |
| --format text/json | text | Saída humana ou JSON estruturado |
| --fail-on info/low/moderate/high/critical | high | Severidade mínima para exit 1 |
| --skip-outdated | desligado | Omite consulta de versões |
| --timeout SEGUNDOS | 60 | Timeout por comando npm; 5 a 300 segundos |
| --help / --version | — | Ajuda ou versão |

### Códigos de saída para automações

- **0**: auditoria executada sem pacotes acima do limiar configurado.
- **1**: pelo menos um pacote afetado no limiar de severidade definido.
- **2**: falha operacional (projeto inválido, lockfile ausente, npm indisponível, erro de rede ou resposta inválida).

Uma falha apenas da consulta suplementar npm outdated é registrada como aviso e deixa outdated: null. Ela não mascara o resultado da auditoria de vulnerabilidades.

As contagens representam **pacotes afetados**, não quantidade de CVEs ou advisories individuais.

## CI/CD

Execute o binário compilado em seu pipeline, apontando para o diretório do projeto-alvo e selecionando o limiar. Por exemplo:

    node /caminho/depscanx/bin/cli.js --path . --fail-on high --format json

Também pode instalar DepScanX como dependência de desenvolvimento do projeto-alvo e executar via npx --no-install. Não confunda um erro operacional (código 2) com uma análise limpa.

## Testes

    npm run typecheck
    npm test
    npm pack --dry-run

A matriz de CI valida Node.js 22/24 em Ubuntu, Windows e macOS, executando compilação, 15 testes isolados, empacotamento e auditoria das próprias dependências.

## Escopo e limites

- Suporte a projetos **npm com lockfile**. Não analisa diretamente yarn, pnpm, Deno ou projetos Python.
- A auditoria depende da disponibilidade e qualidade dos avisos do registro npm.
- As consultas npm podem enviar metadados de dependências ao registro configurado pelo operador.
- **Pacotes abandonados:** ainda **não** há detecção de abandono/manutenção nesta versão. npm outdated detecta defasagem, o que não comprova abandono.
- Não é uma solução SCA completa nem substitui análise manual ou SBOM.

MIT. Consulte [SECURITY.md](SECURITY.md).
