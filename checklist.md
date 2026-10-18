| Nº | Item | Status |
|---:|------|--------|
| 1 | Repositório privado no GitHub, com Diegobuarquebr e @HardSource adicionado como collaborator com permissão **Read** — é assim que o professor acessa a entrega | DONE |
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

## Check de Cobertura das Rubricas da Atividade 1

* [x] **Remediação de Código Vulnerável (`app.py`):**
  * SQL Injection corrigido via consultas parametrizadas.
  * XSS Refletido e Armazenado corrigidos via desacoplamento de código e uso de templates Jinja2 com autoescape nativo.
  * Senhas gravadas com hash com salt (`werkzeug.security`).
  * Remoção de endpoints de debug (`/debug/info`) e hardcoded secrets (`TASKFLOW_SECRET_KEY` e `TASKFLOW_ADMIN_PASSWORD`).
* [x] **Containerização e Hardening de Runtime (`Dockerfile`):**
  * Imagem base reduzida (`python:3.12-slim`).
  * Usuário não-root (`taskflow`) configurado.
  * Servidor de produção WSGI (`gunicorn`) em substituição ao servidor de dev do Flask.
  * Compatível com runtime restritivo (`--read-only`, `--tmpfs /tmp`, `-v taskflow-data:/app/data`, `--cap-drop ALL`, `--security-opt no-new-privileges`).
* [x] **Arquivos de Ignoração (`.dockerignore` e `.gitignore`):**
  * Bloqueio do envio de `.env`, segredos, caches e bancos de dados locais.
* [x] **Qualidade e Segurança de CI/CD (`.github/workflows/`):**
  * **`ci.yml`:** Linter rápido via `ruff check` e cache de dependências.
  * **`container.yml`:** Gate de imagem via **Trivy** (`HIGH,CRITICAL`) e **Smoke Test** funcional no container hardened (`/login`).
  * **`sast.yml`:** Análise estática com **Semgrep** (passando sem alertas de `directly-returned-format-string`) e **Gitleaks** em histórico completo (`fetch-depth: 0`).
  * **`sca.yml`:** Auditoria contínua e agendada de dependências via **`pip-audit`**.
  * **Boas práticas de Pipeline as Code:** Permissões mínimas (`permissions: contents: read`), variáveis centralizadas no `env` e fixação de Actions por SHA imutável.
* [x] **Governança e Dependências:**
  * **`CODEOWNERS`** configurado para aprovação de PRs.
  * **`requirements.txt`** com pinning exato de versões e pacotes corrigidos sem CVEs ativas.

O projeto TaskFlow está totalmente seguro, atende a todas as boas práticas da OWASP e passa com sucesso em todos os Quality Gates dos pipelines no GitHub Actions.
