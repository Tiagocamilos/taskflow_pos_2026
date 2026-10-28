# IaC seguro — Compose, Terraform e scan no pipeline (Módulo 5)

## Resumo

| | Antes | Depois |
|---|---|---|
| Trivy config no Terraform (HIGH/CRITICAL) | **8** (7 HIGH, 1 CRITICAL) | **0** (1 supressão justificada) |
| Checkov no Terraform | **16 falhas**, 9 aprovados | **0 falhas**, 41 aprovados, 7 skips justificados |
| `terraform validate` | — | passando (no `iac-scan.yml`) |
| Banco exposto ao host | sim (exemplo da aula) | não (`nc -zv localhost 5432` → connection refused) |
| Senhas no Compose versionado | sim (`admin123`, `taskflow_pass_secure`, `admin/admin` do Grafana) | não: tudo via `.env` com `${VAR:?}` |
| Loki exposto no host (3100) | sim | não |

## Docker Compose

Dois arquivos:

| Arquivo | Serviços | Como subir (na raiz do repositório) |
|---|---|---|
| `infra/docker-compose.yml` | `web` (TaskFlow) + `db` (PostgreSQL) | `docker compose -f infra/docker-compose.yml --env-file .env up -d --build` |
| `docker-compose.yml` | Grafana + Loki + Promtail | `docker compose --env-file .env up -d` |

### Decisão: PostgreSQL "simulado"

A TaskFlow usa SQLite. Seguindo a Aula 6 (Lab 07), o serviço `db` é o banco **simulado**: representa o banco de produção e serve para aplicar a orquestração segura (rede interna, sem porta no host, segredo via `.env`). A aplicação não foi migrada para PostgreSQL — o foco do módulo é a orquestração, não a camada de persistência.

### Controles aplicados (`infra/docker-compose.yml`)

| Exigência | Implementação |
|---|---|
| Redes frontend/backend isoladas | `web` em `frontend` + `backend`; `db` só em `backend`; `backend` é `internal: true` (sem saída para a internet) |
| Banco sem porta exposta ao host | `db` sem bloco `ports:` |
| Segredos via `.env` (não versionado) + `.env.example` | `${VAR:?defina no .env}`: o Compose **falha** se a variável faltar; nenhum valor padrão no arquivo |
| `read_only` | `web` com filesystem somente leitura; escrita só em `tmpfs /tmp` e nos volumes de dados e logs |
| Healthcheck | `web`: Python `urllib` em `/login` (a imagem alpine não tem `curl`); `db`: `pg_isready`; `web` só sobe com `db` saudável |
| Limites de CPU e memória | `deploy.resources.limits` nos dois serviços |
| `no-new-privileges` | `security_opt` nos dois serviços; `web` também com `cap_drop: [ALL]` |

### Problemas do `infra/docker-compose.yml` anterior

| Problema | Consequência |
|---|---|
| `${POSTGRES_PASSWORD:-taskflow_pass_secure}`, `${TASKFLOW_ADMIN_PASSWORD:-admin123}`, `SECRET_KEY` padrão | se a variável faltasse, subia **silenciosamente** com senha conhecida; valores versionados |
| `.env` não era lido (rodando da raiz, o Compose procurava `infra/.env`) | sempre caía nos valores padrão acima |
| Healthcheck com `curl` | `curl` não existe na imagem; o `web` nunca ficava saudável |
| `read_only` sem volume para o SQLite | a aplicação não conseguia criar o banco e não subia |
| `DATABASE_URL` com a senha no `web` | senha visível no `docker inspect` sem necessidade |

Também foram removidos `infra/Dockerfile` (não usado; fazia `COPY . .` e levaria o `.env` para a imagem) e `infra/requirements.txt` (cópia não auditada pelo `pip-audit`).

### Verificações executadas

```bash
nc -zv localhost 5432                                        # connection refused
docker ps --format '{{.Names}}\t{{.Ports}}' | grep taskflow-   # só web:5000 e grafana:3000 publicados
docker inspect --format '{{.Name}} {{.State.Health.Status}}' taskflow-web taskflow-db   # healthy
curl -s -m 3 localhost:3100/ready || echo "Loki nao exposto"
```

## Terraform (`infra/main.tf`)

Corrigido a partir do `main.insecure.tf` da Aula 6.

| Falha do `main.insecure.tf` | Correção |
|---|---|
| 1. Sem tags | `default_tags` no provider (Projeto, Ambiente, Owner) |
| 2. Bloqueio de acesso público desligado | `aws_s3_bucket_public_access_block` com os 4 campos `true` |
| 3. ACL `public-read` | ACLs desativadas (`BucketOwnerEnforced`); acesso só via IAM |
| 4. Sem criptografia | SSE-KMS com chave do cliente (`aws_kms_key`, rotação automática, política explícita) |
| 5. Sem versionamento | `aws_s3_bucket_versioning` habilitado |
| 6. SSH aberto para `0.0.0.0/0` | sem SSH; entrada só HTTPS de `var.allowed_cidr`, com `validation` que **recusa** `0.0.0.0/0` |
| 7. Egress irrestrito | saída só HTTPS para `var.egress_cidr` (faixa interna, também validada) |
| Extra: sem logging | `aws_s3_bucket_logging` para um bucket de logs dedicado (privado, versionado, com retenção) |
| Extra: sem ciclo de vida | expira versões antigas e aborta uploads incompletos |

### Supressões (todas inline, com justificativa)

| Recurso | Regra | Justificativa |
|---|---|---|
| bucket de logs | CKV_AWS_18 | é o próprio destino dos logs; logar o bucket de logs criaria recursão |
| bucket de logs | CKV_AWS_145 / Trivy AWS-0132 | o destino de server access logging do S3 só aceita SSE-S3 (AES256), não SSE-KMS — limitação da AWS, citada na própria descrição da regra do Trivy |
| buckets de dados e de logs | CKV_AWS_144 | replicação entre regiões fora do escopo/custo do laboratório; versionamento cobre recuperação |
| buckets de dados e de logs | CKV2_AWS_62 | nenhum consumidor de eventos; notificações sem consumidor não agregam controle |
| security group | CKV2_AWS_5 | não há EC2/ALB neste módulo; o SG é a definição que será anexada na implantação |

## `iac-scan.yml`

Arquivo: `.github/workflows/iac-scan.yml` — roda em todo PR para a `main`, em push na `main` e manualmente.

| Passo | Gate |
|---|---|
| `terraform fmt -check` | formatação |
| `terraform init -backend=false` + `terraform validate` | sintaxe e consistência, sem credenciais AWS |
| Checkov (`framework: terraform`, `soft_fail: false`) | falha com qualquer achado não suprimido |
| Trivy config (`HIGH,CRITICAL`, `exit-code: 1`) | falha com qualquer achado HIGH/CRITICAL |
| `docker compose config -q` dos dois Composes | sintaxe e variáveis obrigatórias (valores aleatórios descartáveis no CI) |

Decisões de desenho:

- **Sem filtro `paths:`.** O IaC é required check na `main`; com `paths:`, PRs que não tocam em infraestrutura ficariam esperando um check que nunca roda. O scan leva cerca de 1 minuto, então rodar sempre é o custo aceito.
- **`skip-dirs: codigo`** no Trivy: a pasta `codigo/` é material de referência das aulas, inseguro de propósito, e não faz parte da aplicação.
- **Actions fixadas por SHA** (`checkout`, `setup-terraform`, `checkov-action`, `trivy-action`) e `permissions: contents: read`.
- Versão anterior do workflow quebrava com `--framework compose` (inexistente no Checkov) e usava actions `@master`.

## Demonstração sugerida

PR alterando o padrão de `allowed_cidr` para `0.0.0.0/0` → `terraform validate` falha pela `validation` da variável → check **IaC** vermelho. Ou removendo o `aws_s3_bucket_public_access_block` → Checkov e Trivy acusam o bucket público.

## Evidências

- Run do PR #19 com o **IaC Security Scan** verde.
- Saída local do Checkov e do Trivy no `main.insecure.tf` (antes) e no `infra/main.tf` (depois).
- Print do `docker ps` com o `db` sem porta publicada e do `nc` recusado.
