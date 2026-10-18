| Nº | Item | Status |
|---:|------|--------|
| 1 | Repositório privado no GitHub, com @HardSource adicionado como collaborator com permissão **Read** — é assim que o professor acessa a entrega | ? |
| 2 | **Aula 1** — Branch `main` protegida: Pull Request obrigatório, required status checks e CODEOWNERS | DONE |
| 3 | **Aula 1** — `ci.yml` disparando em `pull_request`, em `push` na `main` e em `workflow_dispatch`, com instalação de dependências e lint (ruff ou flake8) | DONE |
| 4 | **Aula 2** — `sast.yml` com Semgrep (`p/python`, `p/flask`, `p/security-audit`, `--error`) e Gitleaks com `fetch-depth: 0` | DONE |
| 5 | **Aula 2** — Correção no código de SQL Injection (consultas parametrizadas), `SECRET_KEY` lida de variável de ambiente e senhas com hash | DONE |
| 6 | **Aula 3** — `sca.yml` com `pip-audit` como gate, `requirements.txt` atualizado e `.github/dependabot.yml` configurado | DONE |
| 7 | **Aula 3** — `Dockerfile` corrigindo as seis falhas documentadas: imagem base com tag fixada e mínima, `USER` não-root, nenhum segredo em `ENV`/`ARG`, servidor de produção (gunicorn) e debug desligado | DONE |
| 8 | **Aula 3** — Job que builda a imagem e roda `trivy image` como gate para `HIGH,CRITICAL` | DONE |
| 9 | **Aula 3** — `docs/hardening.md` com: Trivy antes × depois, `docker history` antes × depois | |
| 10 | `permissions:` mínimo em todos os workflows e pinning das actions de terceiros | DONE |
| 11 | Demonstração do shift-left: uma vulnerabilidade introduzida em PR (ex.: uma query concatenada ou um token de teste), bloqueando o merge, e corrigida | |
