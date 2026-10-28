# DAST — OWASP ZAP no pipeline (Módulo 4)

## Resumo

| | Antes | Depois |
|---|---|---|
| Alertas do ZAP Baseline (WARN) | **8** | **0** |
| Alertas aceitos com justificativa (IGNORE) | 0 | 4 (`.zap/rules.tsv`) |
| Regras aprovadas (PASS) | 60 | 64 |
| Páginas analisadas pelo ZAP | só `/login` (sem autenticação) | `/login`, `/tasks`, `/tasks/new`, `/logout` (scan autenticado) |
| XSS armazenado / refletido | presente | corrigido (Jinja2 com autoescape) |
| `/debug/info` (vazava a `SECRET_KEY`) | público | removido |

## Como o `dast.yml` funciona

Arquivo: `.github/workflows/dast.yml` — roda em todo PR para a `main`, em push na `main` e manualmente (`workflow_dispatch`).

1. **Build** da imagem com o `Dockerfile` hardened da Atividade 1.
2. Gera uma **senha de admin descartável** por execução (mascarada nos logs).
3. **Sobe a TaskFlow** no runner com as mesmas flags seguras do `container.yml`: `--read-only`, `--cap-drop ALL`, `no-new-privileges`, `SECRET_KEY` aleatória.
4. **Espera ativa** até `/login` responder (até 30 tentativas). Sem isso o ZAP poderia atacar uma aplicação que ainda não subiu e gerar um relatório "limpo" que não prova nada.
5. **Login** com `curl` e captura do cookie de sessão.
6. **Canário de XSS armazenado**: cria uma tarefa cuja descrição é `<script src="https://xss-canary.example/payload.js"></script>`.
7. **ZAP Baseline autenticado** (`zaproxy/action-baseline`, fixada por SHA): o cookie é injetado em todas as requisições (replacer), então o ZAP analisa as páginas logadas.
8. **Relatório** publicado como artefato (`zap-baseline-report`) e container derrubado.

### Por que o gate é real

- `fail_action: true`: **qualquer** alerta que não esteja no `.zap/rules.tsv` falha o job.
- Não existe `continue-on-error` nem regras rebaixadas em massa: só 4 regras estão como IGNORE, cada uma com justificativa.
- **Canário:** com o autoescape funcionando, o `<script src=...>` aparece como texto. Se alguém reintroduzir o XSS (ex.: `| safe` no `tasks.html`), a tag vai crua para o HTML e o ZAP acusa a regra **10017 (Cross-Domain JavaScript Source File Inclusion)**, bloqueando o merge.

## Antes × depois

### Antes — ZAP Baseline contra a versão da Atividade 1 (sem cabeçalhos de segurança)

| ID | Alerta | Risco | OWASP Top 10 2025 |
|---|---|---|---|
| 10020 | Missing Anti-clickjacking Header | Medium | A02 — Security Misconfiguration |
| 10038 | Content Security Policy (CSP) Header Not Set | Medium | A02 — Security Misconfiguration |
| 10202 | Absence of Anti-CSRF Tokens | Medium | A01 — Broken Access Control |
| 10021 | X-Content-Type-Options Header Missing | Low | A02 — Security Misconfiguration |
| 10063 | Permissions Policy Header Not Set | Low | A02 — Security Misconfiguration |
| 90004 | Cross-Origin-Embedder-Policy Header Missing | Low | A02 — Security Misconfiguration |
| 10049 | Non-Storable Content | Informativo | — |
| 10111 | Authentication Request Identified | Informativo | — |

Resultado: `FAIL-NEW: 0  WARN-NEW: 8  IGNORE: 0  PASS: 60`.

### Depois — local e no pipeline

Resultado local (sem autenticação): `WARN-NEW: 0  IGNORE: 3  PASS: 65`.
Resultado no pipeline (autenticado): `WARN-NEW: 0  IGNORE: 4  PASS: 64` — todos os checks do PR verdes.

## Correções no código

| Problema | Correção | OWASP Top 10 2025 |
|---|---|---|
| XSS armazenado na descrição da tarefa | HTML migrado de f-strings para templates Jinja2 com autoescape; nenhum `\| safe` | A05 — Injection |
| XSS refletido no parâmetro `q` da busca | `value="{{ search }}"` com autoescape (aspas e `< >` escapados) | A05 — Injection |
| Mensagem de erro do login | renderizada via template, com autoescape | A05 — Injection |
| `/debug/info` público, vazando versão, plataforma e `SECRET_KEY` | rota removida | A02 — Security Misconfiguration |
| `debug=True` (Werkzeug debugger = execução remota de código) | debug controlado por `FLASK_DEBUG`, **desligado por padrão**; em container roda gunicorn | A02 — Security Misconfiguration |
| Cabeçalhos de segurança ausentes | `after_request` com CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, COEP/COOP/CORP | A02 — Security Misconfiguration |
| Estilo inline bloqueado pela CSP | CSS movido para `static/style.css` (CSP sem `'unsafe-inline'`) | A02 — Security Misconfiguration |
| Comentários HTML (`<!-- -->`) com `{{ }}` nos templates: o Jinja2 executava a expressão (erro 500) e o conteúdo chegava ao navegador | comentários trocados por `{# #}` (removidos no servidor) | A02 / A05 |
| *Race condition* no `init_db()`: dois workers do gunicorn criavam o admin ao mesmo tempo e o container não subia com banco vazio (revelado pelo DAST, que sobe a app do zero) | `INSERT OR IGNORE` (criação idempotente) | A10 — Mishandling of Exceptional Conditions |

## Regras aceitas no `.zap/rules.tsv`

| ID | Ação | Justificativa |
|---|---|---|
| 10049 | IGNORE | Informativo: indica que as respostas não ficam em cache, comportamento desejado para páginas com sessão. |
| 10111 | IGNORE | Informativo: o ZAP apenas identifica o formulário de login; não é vulnerabilidade. |
| 10202 | IGNORE | **Risco aceito**: o cookie de sessão tem `SameSite=Lax` e não é enviado em POST cross-site pelos navegadores atuais. Falta a defesa em profundidade (token CSRF), registrada como melhoria abaixo. |
| 10031 | IGNORE | **Falso positivo comprovado**: o `q` volta no `value` do campo de busca, mas o autoescape escapa aspas e `< >`. Teste abaixo. |

### Evidência do 10031 (teste manual)

Requisição autenticada com o payload `"><script>alert(1)</script>` no `q`:

```
GET /tasks?q=%22%3E%3Cscript%3Ealert(1)%3C/script%3E
```

HTML devolvido:

```html
<input type="text" name="q" placeholder="buscar tarefa" value="&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;">
```

O payload não fecha o atributo nem vira tag: o reflexo não é explorável.

## Defesa em profundidade contra XSS

| Camada | Efeito |
|---|---|
| Autoescape do Jinja2 | `<script>` vira `&lt;script&gt;` e é exibido como texto |
| CSP `default-src 'self'` sem `'unsafe-inline'` | mesmo que um script chegue cru ao HTML, o navegador não executa script inline |
| Cookie de sessão `HttpOnly` | JavaScript não lê o cookie (`document.cookie` vem vazio) |

Demonstração local: com `| safe` no template e a CSP removida, o `alert` dispara; com `| safe` e CSP ligada, o console mostra *"Refused to execute inline script"*; com a correção, o texto aparece literal.

## Demonstração do gate no PR

1. PR alterando `templates/tasks.html`: `{{ row["description"] }}` → `{{ row["description"] | safe }}`.
2. O canário plantado pelo pipeline vai cru para `/tasks` → ZAP acusa **10017** → check **DAST** vermelho → merge bloqueado (required check).
3. Remover o `| safe` → check verde.

## Melhorias registradas (fora do escopo desta entrega)

- Token CSRF em todos os formulários (ex.: Flask-WTF) — remove o aceite do 10202.
- Rate limiting no `/login` (ver runbook de força bruta).
- Scan ativo (ZAP full scan) periódico, fora do caminho crítico do PR.

## Evidências

- Run do PR #18 com todos os checks verdes (incluindo o DAST autenticado).
- Artefato `zap-baseline-report` do run.
- Prints: XSS como texto na lista de tarefas; alerta disparando na branch de demonstração.
