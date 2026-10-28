# Relatório de Análise Dinâmica de Segurança (DAST) - OWASP ZAP

## 1. Visão Geral
Este documento registra a análise dinâmica de segurança executada com a ferramenta OWASP ZAP contra a aplicação TaskFlow integrada ao pipeline de CI/CD.

## 2. Comparativo de Achados: Antes vs. Depois

Antes:
| ID | Alerta | Risco ZAP | Decisão |
|------:|--------|:---------:|---------|
| 10020 | Missing Anti-clickjacking Header | 🟠 Medium | **Corrigir:** `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` |
| 10038 | CSP Header Not Set | 🟠 Medium | **Corrigir:** `Content-Security-Policy` |
| 10021 | X-Content-Type-Options Missing | 🟡 Low | **Corrigir:** `nosniff` |
| 10063 | Permissions Policy Not Set | 🟡 Low | **Corrigir:** `Permissions-Policy` |
| 90004 | COEP Missing | 🟡 Low | **Corrigir:** `Cross-Origin-Embedder-Policy` (+ COOP/CORP) |
| 10049 | Non-Storable Content | 🔵 Info | **IGNORE justificado:** o ZAP só informa que as respostas não ficam em cache, que é o desejado |
| 10111 | Authentication Request Identified | 🔵 Info | **IGNORE justificado:** ele só identifica o formulário de login |
| 10202 | Absence of Anti-CSRF Tokens | 🟠 Medium | **Decisão do grupo** (ver [abaixo](#decisão-sobre-anti-csrf-10202)) |

Depois:

XXXX


### Antes da Correção (Linha de Base Vulnerável)
## Resultado

| Status | Antes | Depois |
|--------|:-----:|:------:|
| ⚠️ WARN-NEW | 8 | **0** |
| ⏭️ IGNORE (justificados) | 0 | **3** |
| ✅ PASS | 60 | **65** |


* **Achado 1**: Stored Cross-Site Scripting (XSS) no campo de descrição de tarefas e parâmetro `og`.
  * **Categorização OWASP Top 10 (2025)**: A05:2025 – Injection.
  * **Evidência**: Payload `<script>alert('XSS')</script>` sendo executado no navegador ao listar tarefas.
    <img width="823" height="376" alt="{BA32F119-0146-417D-8B7F-08D99AEA0EB6}" src="https://github.com/user-attachments/assets/5288a1a3-d90e-4711-b638-27e0294b1323" />

* **Achado 2**: Exposição de Endpoint de Debug (`/debug/info`).
  * **Categorização OWASP Top 10 (2025)**: A02:2025 – Security Misconfiguration.
  * **Evidência**: Rota `/debug/info` retornando chaves internas e versão da plataforma em JSON sem autenticação.

### Depois da Correção
* **XSS Armazenado**: Mitigado. A aplicação passou a adotar o motor de templates Jinja2 com autoescape habilitado por padrão em todos os pontos de saída.
* **Endpoint de Debug**: Removido. A rota foi excluída e o modo debug Flask passa a ser controlado estritamente via variável de ambiente `FLASK_DEBUG=0`.

## 3. Matriz de Mapeamento OWASP Top 10 (2025)

| Alerta ZAP | Categoria OWASP 2025 | Status | Ação Adotada |
| :--- | :--- | :--- | :--- |
| Stored XSS | A05:2025 - Injection | Corrigido | Uso de templates Jinja2 sem filtro `\| safe`. |
| Debug Endpoint Exposed | A02:2025 - Security Misconfiguration | Corrigido | Remoção do endpoint e controle por env. |
| Absence of Anti-CSRF Tokens | A07:2025 - Authentication Failures | Aceito (WARN) | Registrado no `.zap/rules.tsv`. |

## Decisão sobre Anti-CSRF (10202)

<!-- Descreva aqui a decisão do grupo e a justificativa -->

