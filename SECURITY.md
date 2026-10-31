# Segurança e divulgação responsável

Utilize GitHub Security Advisories (quando disponível) para reportar vulnerabilidades de forma privada. Nunca inclua tokens npm, credenciais, manifests privados ou relatórios confidenciais em issues públicas.

O DepScanX normaliza a saída de npm audit e npm outdated; **não executa** npm audit fix, npm install ou scripts do projeto-alvo durante a análise. Os comandos consultam o registro configurado no npm e podem divulgar metadados das dependências.

Execute scans de projetos não confiáveis com permissões mínimas e, preferencialmente, em ambiente isolado. O scanner não é detector de malware ou dependências maliciosas e não comprova ausência de vulnerabilidades. Dependências abandonadas não são detectadas automaticamente na versão 1.1.0.

A ferramenta rejeita erro operacional de auditoria com código 2, em vez de apresentar resultado limpo. A saída humana neutraliza caracteres de controle e sequências ANSI provenientes dos metadados.
