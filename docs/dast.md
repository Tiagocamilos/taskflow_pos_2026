# Relatório de Análise Dinâmica de Segurança (DAST) — OWASP ZAP

## 1. Visão geral

Este documento registra a análise dinâmica de segurança executada com o OWASP ZAP contra a TaskFlow **em execução**, integrada ao pipeline de CI/CD (`.github/workflows/dast.yml`).

| | Antes | Depois |
|---|:---:|:---:|
| ⚠️ Alertas do ZAP (WARN-NEW) | 8 | **0** |
| ⏭️ Aceitos com justificativa (IGNORE) | 0 | **4** (`.zap/rules.tsv`) |
| ✅ Regras aprovadas (PASS) | 60 | **64** |
| Páginas analisadas | só `/login` (sem autenticação) | `/login`, `/tasks`, `/tasks/new`, `/logout` (scan autenticado) |
| XSS armazenado e refletido | presente | corrigido |
| `/debug/info` (vazava a `SECRET_KEY`) | público | removido |

## 2. Como o `dast.yml` funciona

Roda em todo PR para a `main`, em push na `main` e manualmente (`workflow_dispatch`).

1. **Build** da imagem com o `Dockerfile` hardened da Atividade 1.
2. Gera uma **senha de admin descartável** por execução (mascarada nos logs).
3. **Sobe a TaskFlow** no runner com as mesmas flags seguras do `container.yml` (`--read-only`, `--cap-drop ALL`, `no-new-privileges`, `SECRET_KEY` aleatória).
4. **Espera ativa** até `/login` responder. Sem isso o ZAP poderia atacar uma aplicação que ainda não subiu e gerar um relatório "limpo" que não prova nada.
5. **Login** com `curl` e captura do cookie de sessão.
6. **Canário de XSS armazenado**: cria uma tarefa com a descrição `<script src="https://xss-canary.example/payload.js"></script>`.
7. **ZAP Baseline autenticado** (`zaproxy/action-baseline`, fixada por SHA): o cookie é injetado em todas as requisições, então o ZAP analisa as páginas logadas.
8. **Relatório** publicado como artefato (`zap-baseline-report`) e container derrubado.

### Por que o gate é real

- `fail_action: true`: **qualquer** alerta que não esteja no `.zap/rules.tsv` falha o job e bloqueia o merge.
- Sem `continue-on-error` e sem regras rebaixadas em massa: só 4 regras estão como IGNORE, cada uma justificada.
- **Canário:** com o autoescape funcionando, o `<script src=...>` aparece como texto. Se alguém reintroduzir o XSS (ex.: `| safe` no `tasks.html`), a tag vai crua para o HTML e o ZAP acusa a regra **10017 (Cross-Domain JavaScript Source File Inclusion)**.

## 3. Comparativo de achados: antes × depois

### Antes — ZAP Baseline contra a versão da Atividade 1

| ID | Alerta | Risco ZAP | Decisão | Depois |
|------:|--------|:---------:|---------|:------:|
| 10020 | Missing Anti-clickjacking Header | 🟠 Medium | **Corrigir:** `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` | ✅ PASS |
| 10038 | CSP Header Not Set | 🟠 Medium | **Corrigir:** `Content-Security-Policy` | ✅ PASS |
| 10021 | X-Content-Type-Options Missing | 🟡 Low | **Corrigir:** `nosniff` | ✅ PASS |
| 10063 | Permissions Policy Not Set | 🟡 Low | **Corrigir:** `Permissions-Policy` | ✅ PASS |
| 90004 | COEP Missing | 🟡 Low | **Corrigir:** `Cross-Origin-Embedder-Policy` (+ COOP/CORP) | ✅ PASS |
| 10049 | Non-Storable Content | 🔵 Info | **IGNORE justificado:** só informa que as respostas não ficam em cache, que é o desejado | ⏭️ IGNORE |
| 10111 | Authentication Request Identified | 🔵 Info | **IGNORE justificado:** só identifica o formulário de login | ⏭️ IGNORE |
| 10202 | Absence of Anti-CSRF Tokens | 🟠 Medium | **Risco aceito** (ver [seção 5](#5-decisão-sobre-anti-csrf-10202)) | ⏭️ IGNORE |

Resultado: `WARN-NEW: 8  IGNORE: 0  PASS: 60`.

### Achado novo no scan autenticado (pipeline)

| ID | Alerta | Onde | Decisão | Depois |
|------:|--------|------|---------|:------:|
| 10031 | User Controllable HTML Element Attribute (Potential XSS) | `/tasks?q=ZAP` | **Falso positivo comprovado** (ver seção 6) | ⏭️ IGNORE |

### Depois

- Local (sem autenticação): `WARN-NEW: 0  IGNORE: 3  PASS: 65`.
- Pipeline (autenticado): `WARN-NEW: 0  IGNORE: 4  PASS: 64` — todos os checks do PR verdes.

### Achados da linha de base vulnerável (aplicação original)

* **Achado 1**: XSS armazenado no campo de descrição de tarefas e XSS refletido no parâmetro `q` da busca.
  * **OWASP Top 10 (2025)**: A05:2025 – Injection.
  * **Evidência**: payload `<script>alert('XSS')</script>` executado no navegador ao listar tarefas.
  <img width="1270" height="461" alt="result-dast" src="https://github.com/user-attachments/assets/8100b8d2-e404-44c5-af56-436e76152db4" />

* **Achado 2**: endpoint de debug exposto (`/debug/info`).
  * **OWASP Top 10 (2025)**: A02:2025 – Security Misconfiguration.
  * **Evidência**: rota `/debug/info` retornando a `SECRET_KEY`, a versão do Python e a plataforma em JSON, sem autenticação.

### Depois da correção

* **XSS**: mitigado. Toda a saída HTML passou para templates Jinja2 com autoescape (descrição, título, parâmetro `q` e mensagem de erro do login), sem `| safe`. O payload agora aparece como texto literal.
* **Endpoint de debug**: removido. O modo debug é controlado pela variável `FLASK_DEBUG`, **desligado por padrão**; em container a aplicação roda com gunicorn.

## 4. Matriz de mapeamento OWASP Top 10 (2025)

| Achado | Categoria OWASP 2025 | Status | Ação adotada |
| :--- | :--- | :--- | :--- |
| XSS armazenado (descrição) e refletido (`q`, erro do login) | A05:2025 – Injection | Corrigido | Templates Jinja2 com autoescape, sem `\| safe` |
| Endpoint `/debug/info` e `debug=True` | A02:2025 – Security Misconfiguration | Corrigido | Rota removida; debug via `FLASK_DEBUG`, desligado por padrão |
| Cabeçalhos ausentes (10020, 10038, 10021, 10063, 90004) | A02:2025 – Security Misconfiguration | Corrigido | `after_request` com CSP, X-Frame-Options, nosniff, Permissions-Policy, COEP/COOP/CORP |
| Comentários HTML com `{{ }}` nos templates (erro 500 e conteúdo vazando ao navegador) | A02:2025 – Security Misconfiguration | Corrigido | Comentários trocados por `{# #}` (removidos no servidor) |
| Absence of Anti-CSRF Tokens (10202) | A01:2025 – Broken Access Control | Aceito (IGNORE justificado) | `SameSite=Lax`; token CSRF registrado como melhoria |
| Potential XSS em atributo (10031) | A05:2025 – Injection | Falso positivo (IGNORE) | Teste manual comprovando o escape |
| *Race condition* no `init_db()` com vários workers do gunicorn (revelada pelo DAST, que sobe a app do zero) | A10:2025 – Mishandling of Exceptional Conditions | Corrigido | `INSERT OR IGNORE` (criação idempotente do admin) |

## 5. Decisão sobre Anti-CSRF (10202)

O grupo **aceitou o risco**, com justificativa registrada no `.zap/rules.tsv`:

- O cookie de sessão é configurado com `SESSION_COOKIE_SAMESITE = "Lax"` e `HttpOnly`. Navegadores atuais **não enviam** esse cookie em requisições POST vindas de outro site, que é exatamente o vetor de um ataque CSRF.
- O que falta é a **defesa em profundidade** (token CSRF em cada formulário).

**Trade-off discutido:** implementar o token (ex.: Flask-WTF) adicionaria uma dependência e exigiria que o script de simulação de força bruta (Módulo 6) buscasse o token antes de cada tentativa. Optamos por manter o escopo e registrar o token CSRF como **melhoria**.

## 6. Evidência do falso positivo 10031

Requisição autenticada com o payload `"><script>alert(1)</script>` no parâmetro `q`:

```
GET /tasks?q=%22%3E%3Cscript%3Ealert(1)%3C/script%3E
```

HTML devolvido:

```html
<input type="text" name="q" placeholder="buscar tarefa" value="&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;">
```

O payload não fecha o atributo nem vira tag: o reflexo não é explorável.

## 7. Defesa em profundidade contra XSS

| Camada | Efeito |
|---|---|
| Autoescape do Jinja2 | `<script>` vira `&lt;script&gt;` e é exibido como texto |
| CSP `default-src 'self'` sem `'unsafe-inline'` | mesmo que um script chegue cru ao HTML, o navegador não executa script inline (por isso o CSS foi movido para `static/style.css`) |
| Cookie de sessão `HttpOnly` | JavaScript não lê o cookie (`document.cookie` vem vazio) |

## 8. Demonstração do gate no PR

1. PR alterando `templates/tasks.html`: `{{ row["description"] }}` → `{{ row["description"] | safe }}`.
2. O canário plantado pelo pipeline vai cru para `/tasks` → ZAP acusa **10017** → check **DAST** vermelho → merge bloqueado (required check).
3. Remover o `| safe` → check verde.

## 9. Melhorias registradas

- Token CSRF em todos os formulários (ex.: Flask-WTF), eliminando o aceite do 10202.
- Rate limiting no `/login` (ver `docs/runbook-login-bruteforce.md`).
- Scan ativo (ZAP full scan) periódico, fora do caminho crítico do PR.
