# Relatório de Hardening - TaskFlow

Este documento registra o **antes × depois** do hardening da imagem Docker
(Trivy e `docker history`), as flags de runtime seguras e a auditoria de SO
com Lynis.

- **Antes:** `codigo/app-exemplo/Dockerfile` (linha de base, `python:latest`)
- **Depois:** `Dockerfile` da raiz (hardened, `python:3.12-slim`, multi-stage)

> Trechos marcados com `TODO` devem ser substituídos pela saída real dos
> comandos indicados.

---

## 1. As seis falhas do Dockerfile original e a correção

| # | Falha (antes) | Correção (depois) |
|---|---|---|
| 1 | `FROM python:latest` — tag mutável, imagem completa (centenas de pacotes) | `python:3.12-slim` com tag fixada + build multi-stage |
| 2 | Nenhum `USER` — processo rodando como **root** | Usuário de sistema `taskflow`, sem shell (`/usr/sbin/nologin`) |
| 3 | `pip install` sem controle de versões | Versões fixadas no `requirements.txt`, auditadas pelo pip-audit; `--no-cache-dir` |
| 4 | `ENV ADMIN_PASSWORD=admin123` gravado na camada | Nenhum segredo em `ENV`/`ARG`; segredos só em runtime (`-e` / `--env-file`) |
| 5 | Servidor de desenvolvimento do Flask na porta 5000 | gunicorn (servidor WSGI de produção) |
| 6 | `CMD ["python", "app.py"]` com `debug=True` e como root | `CMD ["gunicorn", ...]`, sem debug, como usuário não-root |

Extras: `COPY` apenas de `app.py` e `templates/` (antes `COPY . .` levava
`.git`, `.env` e o banco local para a imagem), `.dockerignore`, código
pertencente ao root (somente leitura para a app) e apenas `/app/data` gravável.

---

## 2. Trivy — antes × depois

**Comandos utilizados:**

```bash
# Antes (linha de base)
docker build -t taskflow:vuln codigo/app-exemplo
trivy image --severity HIGH,CRITICAL taskflow:vuln

# Depois (hardened)
docker build -t taskflow:hardened .
trivy image --severity HIGH,CRITICAL --ignore-unfixed taskflow:hardened
```

| | Antes (`python:latest`) | Depois (`python:3.12-slim`) |
|---|---|---|
| SO base | TODO (ex.: debian 13.x) | debian 13.7 |
| Pacotes de SO | TODO | 87 |
| CVEs HIGH | TODO | 0 |
| CVEs CRITICAL | TODO | 0 |
| CVEs em pacotes Python | TODO | 0 |
| Gate no CI | — | `container.yml`, `exit-code: 1` para `HIGH,CRITICAL` |

### Saída do Trivy — antes

```text
TODO: colar aqui o "Report Summary" e a tabela de achados de
trivy image --severity HIGH,CRITICAL taskflow:vuln
```

### Saída do Trivy — depois

Fonte: job *Build da imagem e scan com Trivy* (`container.yml`) —
TODO: colar o link do run no GitHub Actions.

```text
Detected OS  family="debian" version="13.7"
[debian] Detecting vulnerabilities...  os_version="13" pkg_num=87

Report Summary
Target                                            Type        Vulnerabilities
taskflow:<sha> (debian 13.7)                      debian      0
flask-3.1.3 / jinja2-3.1.6 / werkzeug-3.1.9 /     python-pkg  0
markupsafe-3.0.4 / gunicorn-26.2.0 / itsdangerous-2.2.0 /
python-dotenv-1.2.2 / click-8.5.0 / blinker-1.9.0 / pip-25.0.1
```

### Decisão: `--ignore-unfixed`

O gate usa `ignore-unfixed: true`: CVEs **sem correção publicada** não
bloqueiam o merge, porque não existe versão para a qual atualizar — bloquear
só travaria a esteira sem reduzir risco. Esses achados são revisados a cada
build (o Trivy continua listando-os sem a flag) e, se surgirem, são
registrados aqui como **risco aceito**, com o ID da CVE e a justificativa.

Riscos aceitos no momento: **nenhum** (0 HIGH/CRITICAL, com ou sem correção).

---

## 3. `docker history` — antes × depois

**Comandos utilizados:**

```bash
docker history --no-trunc taskflow:vuln
docker history --no-trunc taskflow:hardened
```

### Antes

O segredo fica **gravado na camada** e qualquer pessoa com acesso à imagem
consegue lê-lo:

```text
TODO: colar a saída, destacando a linha:
ENV ADMIN_PASSWORD=admin123
```

### Depois

Nenhuma camada contém segredo. As variáveis de ambiente da imagem são apenas
de configuração (`PYTHONDONTWRITEBYTECODE`, `PYTHONUNBUFFERED`,
`TASKFLOW_DATABASE`). `TASKFLOW_SECRET_KEY` e `TASKFLOW_ADMIN_PASSWORD` são
injetadas só em tempo de execução.

```text
TODO: colar a saída
```

Verificação rápida:

```bash
docker history --no-trunc taskflow:vuln     | grep -i password   # encontra
docker history --no-trunc taskflow:hardened | grep -i password   # vazio
```

---

## 4. Flags de runtime seguras

Usadas no smoke test do `container.yml` e recomendadas para rodar localmente:

```bash
docker run -d --name taskflow -p 5000:5000 \
  --read-only --tmpfs /tmp \
  -v taskflow-data:/app/data \
  --cap-drop ALL --security-opt no-new-privileges \
  --env-file .env \
  taskflow:hardened
```

| Flag | O que protege |
|---|---|
| `--read-only` | Filesystem da imagem imutável: um invasor não altera o código nem instala ferramentas |
| `--tmpfs /tmp` | Área temporária em memória (o gunicorn precisa) |
| `-v taskflow-data:/app/data` | Única pasta gravável (banco SQLite) |
| `--cap-drop ALL` | Remove todas as capabilities do kernel |
| `--security-opt no-new-privileges` | Impede escalada de privilégio via binários setuid |
| `--env-file .env` | Segredos entram só em runtime, nunca na imagem |

Evidência de que a imagem funciona com essas restrições: o smoke test do
`container.yml` sobe o container com todas as flags e faz `curl` em `/login`
(TODO: link do run verde).

Achado durante a implementação: com `--read-only`, a primeira versão falhou com
`sqlite3.OperationalError: unable to open database file`, porque o banco era
criado em `/app`. A correção foi apontar o banco para `/app/data`
(`TASKFLOW_DATABASE`), a única pasta gravável — ou seja, a flag cumpriu o papel
de impedir escrita fora do volume.

---

## 5. Auditoria de SO com Lynis

**Ambiente auditado:** TODO (ex.: VM Ubuntu 24.04 da aula / container de hardening)

**Comandos utilizados:**

```bash
sudo lynis audit system            # antes do hardening
# ... aplicar as correções ...
sudo lynis audit system            # depois
sudo grep -E "hardening_index|warning\[\]|suggestion\[\]" /var/log/lynis-report.dat
```

| | Antes | Depois |
|---|---|---|
| Hardening index | TODO | TODO |
| Warnings | TODO | TODO |
| Suggestions | TODO | TODO |

### Principais achados e tratamento

| Teste (ID) | Achado | Tratamento |
|---|---|---|
| TODO (ex.: SSH-7408) | TODO (ex.: `PermitRootLogin yes`) | Corrigido — TODO |
| TODO | TODO | Corrigido / Aceito — justificativa |
| TODO | TODO | Corrigido / Aceito — justificativa |

O Lynis é ferramenta de **diagnóstico**: não corrige nada sozinho. Cada achado
acima foi corrigido manualmente ou aceito com justificativa.
