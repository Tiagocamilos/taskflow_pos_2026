# TaskFlow DevSecOps — Esteira Segura

Aplicação TaskFlow (Flask) protegida por uma esteira de CI segura no GitHub
Actions. Todo Pull Request para a `main` passa por **build/lint, SAST, secret
scanning, SCA e scan de imagem**; se qualquer gate falhar, o merge é bloqueado.

Atividade 1 da disciplina DevSecOps (Aulas 1, 2 e 3).

## Grupo

| Membro | GitHub | Papel |
|---|---|---|
| Tiago Camilo | @Tiagocamilos | TODO |
| TODO | @dhuberto | TODO |
| TODO | @emcsmalone | TODO |
| TODO | @helierison | TODO |
| TODO | @tongenx | TODO |

---

## Sumário

1. [Estrutura do repositório](#1-estrutura-do-repositório)
2. [Rodar a aplicação localmente](#2-rodar-a-aplicação-localmente)
3. [Rodar com Docker](#3-rodar-com-docker)
4. [A esteira (workflows)](#4-a-esteira-workflows)
5. [Rodar cada scanner localmente](#5-rodar-cada-scanner-localmente)
6. [Proteção da main e CODEOWNERS](#6-proteção-da-main-e-codeowners)
7. [Vulnerabilidades corrigidas](#7-vulnerabilidades-corrigidas)
8. [Decisões técnicas e riscos aceitos](#8-decisões-técnicas-e-riscos-aceitos)
9. [Demonstração do shift-left](#9-demonstração-do-shift-left)

---

## 1. Estrutura do repositório

```text
.
├── app.py                    # Aplicação Flask (versão corrigida)
├── templates/                # Templates Jinja2 (autoescape contra XSS)
├── requirements.txt          # Dependências com versão fixada
├── Dockerfile                # Imagem hardened (multi-stage, não-root, gunicorn)
├── .dockerignore             # Impede .env, .git e banco local na imagem
├── .env.example              # Modelo das variáveis de ambiente (sem valores)
├── docs/
│   └── hardening.md          # Trivy, docker history e Lynis: antes × depois
├── codigo/                   # Material de referência da disciplina (fora dos scans)
└── .github/
    ├── CODEOWNERS            # Quem revisa cada parte do código
    ├── dependabot.yml        # Atualização automática de pip e GitHub Actions
    └── workflows/
        ├── ci.yml            # Build + lint (ruff)
        ├── sast.yml          # Semgrep + Gitleaks
        ├── sca.yml           # pip-audit
        └── container.yml     # Build da imagem + Trivy + smoke test
```

---

## 2. Rodar a aplicação localmente

**Pré-requisitos:** Python 3.12 e Git.

```bash
# 1. Clonar e entrar na pasta
git clone https://github.com/Tiagocamilos/taskflow_pos_2026.git
cd taskflow_pos_2026

# 2. Ambiente virtual e dependências
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. Gerar a SECRET_KEY (copie o valor impresso)
python -c "import secrets; print(secrets.token_hex(32))"

# 4. Criar o .env a partir do modelo
cp .env.example .env               # Windows: copy .env.example .env
```

Abra o `.env` e preencha (sem aspas e sem espaços ao redor do `=`):

```text
TASKFLOW_SECRET_KEY=valor-gerado-no-passo-3
TASKFLOW_ADMIN_PASSWORD=uma-senha-que-voce-escolher
```

```bash
# 5. Subir a app
python app.py
```

Acesse http://127.0.0.1:5001 e entre com o usuário `admin` e a senha definida
em `TASKFLOW_ADMIN_PASSWORD`.

> - O `.env` está no `.gitignore` e **nunca** deve ser commitado.
> - O usuário `admin` só é criado com o banco vazio. Se a app subiu antes de
>   preencher o `.env`, apague o `taskflow.db` e rode de novo.
> - Porta 5001 localmente para evitar conflito com o AirPlay do macOS.

| Variável | Obrigatória | Descrição |
|---|---|---|
| `TASKFLOW_SECRET_KEY` | Sim | Assina o cookie de sessão. Sem ela a app não sobe. |
| `TASKFLOW_ADMIN_PASSWORD` | Não | Senha inicial do `admin` (gravada como hash). Sem ela, nenhum usuário é criado. |
| `TASKFLOW_DATABASE` | Não | Caminho do SQLite. Padrão `taskflow.db`; no container, `/app/data/taskflow.db`. |

---

## 3. Rodar com Docker

```bash
docker build -t taskflow:hardened .

docker run --rm -p 5000:5000 --env-file .env \
  --read-only --tmpfs /tmp -v taskflow-data:/app/data \
  --cap-drop ALL --security-opt no-new-privileges \
  taskflow:hardened
```

Acesse http://localhost:5000.

| Flag | Proteção |
|---|---|
| `--read-only` | Filesystem da imagem imutável |
| `--tmpfs /tmp` | Área temporária em memória (usada pelo gunicorn) |
| `-v taskflow-data:/app/data` | Única pasta gravável (banco SQLite) |
| `--cap-drop ALL` | Remove todas as capabilities do kernel |
| `--security-opt no-new-privileges` | Bloqueia escalada de privilégio via setuid |
| `--env-file .env` | Segredos só em runtime, nunca gravados na imagem |

---

## 4. A esteira (workflows)

Todos os workflows disparam em `pull_request` para a `main`, em `push` na
`main` e manualmente (`workflow_dispatch`, aba **Actions → workflow → Run
workflow**). Todos usam `permissions:` mínimo e actions fixadas por SHA.

| Workflow | Job (required check) | O que faz | Bloqueia o merge quando |
|---|---|---|---|
| `ci.yml` | **Build e Lint** | Instala dependências e roda `ruff check .` | Erro de lint (import faltando, nome indefinido, código morto) |
| `sast.yml` | **SAST - Semgrep** | Semgrep com `p/python`, `p/flask`, `p/security-audit` e `--error` | Qualquer achado (SQLi, XSS, debug, segredo hardcoded...) |
| `sast.yml` | **Secret Scanning - Gitleaks** | Varre **todo o histórico** do Git (`fetch-depth: 0`) | Segredo encontrado em qualquer commit |
| `sca.yml` | **SCA - pip-audit** | Audita o `requirements.txt` contra a base de CVEs da PyPA (`--strict`). Roda também toda segunda às 09:00 UTC | Dependência com CVE conhecida |
| `container.yml` | **Build da imagem e scan com Trivy** | Builda a imagem, roda `trivy image` e sobe o container com as flags seguras (smoke test em `/login`) | CVE HIGH/CRITICAL com correção disponível, ou container que não sobe |

**Dependabot** (`.github/dependabot.yml`): abre PRs semanais atualizando
dependências Python e os SHAs das GitHub Actions. Cada PR do Dependabot passa
pelos mesmos gates.

Evidências (runs verdes): TODO — colar os links dos runs na aba Actions.

---

## 5. Rodar cada scanner localmente

Com o ambiente virtual ativo, na raiz do repositório:

```bash
# Lint
pip install "ruff==0.6.9"
ruff check .

# SAST
pip install "semgrep==1.90.0" "setuptools<81"
semgrep scan --config=p/python --config=p/flask --config=p/security-audit \
  --exclude=codigo --error .

# Secret scanning (histórico completo) - requer o binário do gitleaks
gitleaks detect --source . -v

# SCA
pip install "pip-audit==2.7.3"
pip-audit -r requirements.txt --strict --desc

# Scan da imagem - requer o Trivy instalado
docker build -t taskflow:hardened .
trivy image --severity HIGH,CRITICAL --ignore-unfixed taskflow:hardened
```

Instalação do Gitleaks e do Trivy: `brew install gitleaks trivy` (macOS) ou
conforme a documentação oficial de cada ferramenta.

---

## 6. Proteção da main e CODEOWNERS

Configuração em **Settings → Branches → Branch protection rule** (`main`):

- Pull Request obrigatório, com **1 aprovação** e **review de Code Owners**
- Aprovações descartadas quando há novos commits
- **Required status checks** (os 5 jobs da tabela da seção 4), com a branch
  atualizada antes do merge
- Sem bypass, inclusive para administradores

O `.github/CODEOWNERS` define os revisores. Como ninguém aprova o próprio PR,
cada regra tem mais de um dono.

Evidência: TODO — print do PR com merge bloqueado.

---

## 7. Vulnerabilidades corrigidas

### Aplicação (`app.py`) — detectadas pelo Semgrep

| Vulnerabilidade | Correção |
|---|---|
| SQL Injection no login e na busca | Consultas parametrizadas (`?`) |
| XSS armazenado (HTML com f-string) | Templates Jinja2 com autoescape |
| `SECRET_KEY` hardcoded | Lida de `TASKFLOW_SECRET_KEY`; sem ela a app não sobe |
| Senhas em texto puro | Hash com salt (`werkzeug.security`); senha inicial via ambiente |
| Endpoint `/debug/info` vazando a `SECRET_KEY` | Rota removida |
| `debug=True` e host `0.0.0.0` | Removidos; em produção roda com gunicorn |

Extras: cookie de sessão `HttpOnly` e `SameSite=Lax`, `session.clear()` no
login (evita fixação de sessão).

### Dependências (`requirements.txt`) — pip-audit

Versões atualizadas e fixadas. `PyYAML` e `requests` removidos por não serem
usados pela aplicação (menos superfície de ataque).

### Container (`Dockerfile`) — Trivy

As seis falhas do Dockerfile original foram corrigidas. Detalhes, Trivy e
`docker history` antes × depois e auditoria Lynis em
[`docs/hardening.md`](docs/hardening.md).

---

## 8. Decisões técnicas e riscos aceitos

- **Pin das actions por SHA** em vez de tag (`@v4`): tags podem ser
  re-apontadas para código malicioso; o SHA é imutável. O Dependabot mantém
  os SHAs atualizados.
- **`setuptools<81` no job do Semgrep**: versões novas do setuptools
  removeram o `pkg_resources`, ainda usado por uma dependência do Semgrep 1.90.0.
- **Trivy com `ignore-unfixed`**: CVE sem correção publicada não bloqueia o
  merge (não há versão para atualizar). Se surgir, é registrada em
  `docs/hardening.md` como risco aceito. Hoje: 0 HIGH/CRITICAL.
- **Gitleaks não detectou os segredos didáticos originais** (`SECRET_KEY` e
  `ADMIN_PASSWORD`): são valores de baixa entropia, fora das regras padrão.
  O segredo hardcoded foi pego pelo Semgrep — as ferramentas se complementam.
  Não foi necessária allowlist no `.gitleaks.toml`.
- **`SECRET_KEY` gerada na hora no smoke test** (`openssl rand -hex 32`) em
  vez de um secret do repositório: é descartável e funciona também nos PRs do
  Dependabot, que não recebem os secrets do repositório.
- **Pasta `codigo/` excluída do Semgrep**: contém o material de referência da
  disciplina, com exemplos vulneráveis de propósito.

Supressões (`# nosemgrep`, `--exit-zero`, `continue-on-error`): **nenhuma**.

---

## 9. Demonstração do shift-left

TODO — preencher após o PR de demonstração:

1. PR #TODO introduz uma vulnerabilidade (ex.: query SQL concatenada).
2. O job **SAST - Semgrep** fica vermelho e o merge é bloqueado (link do run).
3. Commit de correção no mesmo PR → todos os checks verdes → merge liberado.
