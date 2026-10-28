# Runbook — Força bruta no login da TaskFlow

| Campo | Valor |
|---|---|
| Referência | NIST SP 800-61 — 4 fases: Preparação; Detecção e Análise; Contenção, Erradicação e Recuperação; Atividade Pós-Incidente |
| Ativo afetado | TaskFlow — rota `POST /login` (container `taskflow`, porta 5000) |
| Fonte de dados | Logs JSON da aplicação → Promtail → Loki → Grafana |
| Categoria OWASP | A07:2025 — Authentication Failures |
| Severidade inicial | **Média** — sobe para **Alta** se houver login bem-sucedido a partir do IP atacante |

## Condição de disparo

> **Mais de 10 falhas de login (`event="login_attempt"`, `result="failure"`) vindas do mesmo IP em uma janela de 5 minutos.**

Um usuário legítimo erra a senha 2 ou 3 vezes; 10 falhas em 5 minutos indicam automação. No exercício abaixo, o analista errou 4 vezes (abaixo do limiar) e os ataques chegaram a 21 e 120 falhas (acima do limiar) — o limiar separa os dois comportamentos.

Condição secundária (ataque distribuído entre vários IPs): **mais de 20 falhas contra o mesmo `username` em 15 minutos**.

### Query de detecção

Grafana → Explore → data source **Loki** → modo **Code**:

```logql
sum by (ip) (count_over_time({job="taskflow", event="login_attempt"} | json | result="failure" [5m]))
```

Qualquer série acima de **10** dispara este runbook. A mesma consulta está salva no painel **"Falhas de login por IP (5 min)"**, no dashboard **"TaskFlow - Segurança"**, com o limiar desenhado como linha tracejada.

---

## Fase 1 — Preparação

O que precisa existir **antes** de um incidente:

- [x] A aplicação registra o evento `login_attempt` com `result`, `username`, `ip` e `request_id`, **sem senha** (detalhes em `docs/observabilidade.md`).
- [x] Stack Grafana + Loki + Promtail sobe com `docker compose up -d`.
- [x] Query de detecção salva em painel, com o limiar visível.
- [x] Simulação de ataque versionada em `scripts/simular-forca-bruta.sh`, para treinar o runbook.
- [x] Acesso `sudo` ao host (bloqueio com `iptables`) e ao `.env` (rotação de segredos).
- [x] Melhoria: regra de alerta no Grafana com a query de detecção e limiar `> 10`.

![Logs JSON no Grafana, com request_id e sem senha](img/runbook-01-logs-json.png)

## Fase 2 — Detecção e Análise

1. **Confirmar o disparo**: rodar a query de detecção nos últimos 15 minutos e anotar o(s) IP(s) e o pico.
2. **Escopo**: quais contas foram alvo?
   ```logql
   sum by (username) (count_over_time({job="taskflow", event="login_attempt"} | json | result="failure" [15m]))
   ```
3. **Comprometimento**: o IP atacante conseguiu entrar? É a pergunta mais importante.
   ```logql
   {job="taskflow", event="login_attempt"} | json | result="success"
   ```
   - Nenhum sucesso vindo do IP atacante → tentativa **sem sucesso**, severidade **Média**.
   - Algum sucesso vindo do IP atacante → **conta comprometida**, severidade **Alta**: executar também a Erradicação.
4. **O que o atacante fez depois** (apenas se entrou): seguir as ações do IP após o login.
   ```logql
   {job="taskflow"} | json | ip="<IP_ATACANTE>" | event=~"tasks_list_accessed|task_created|http_request"
   ```
5. **Registrar** a linha do tempo: início, fim, IP, contas, volume e resultado.

## Fase 3 — Contenção, Erradicação e Recuperação

### Contenção (minutos)

Bloquear o IP atacante no host. A chain `DOCKER-USER` é onde o Docker aplica regras ao tráfego destinado aos containers:

```bash
sudo iptables -I DOCKER-USER -s <IP_ATACANTE> -p tcp --dport 5000 -j DROP
sudo iptables -L DOCKER-USER -n --line-numbers
```

Validação: as requisições do atacante passam a dar timeout e a linha dele no painel **para de subir**.

> **Observação do laboratório:** requisições feitas de dentro da própria VM aparecem com o IP do gateway Docker (`172.17.0.1`). Bloquear esse IP bloquearia o próprio host. Por isso, o teste de contenção foi feito com o ataque partindo de outra máquina (o Mac, `192.168.15.110`).

### Erradicação (somente se houve login com sucesso)

1. **Trocar a senha** da conta afetada, gravando um novo hash no banco:
   ```bash
   read -s -p "Nova senha: " NOVA_PW; echo
   docker exec -e NOVA_PW="$NOVA_PW" taskflow python -c "import os,sqlite3;from werkzeug.security import generate_password_hash as h;db=sqlite3.connect(os.environ['TASKFLOW_DATABASE']);db.execute('UPDATE users SET password=? WHERE username=?',(h(os.environ['NOVA_PW']),'admin'));db.commit()"
   ```
2. **Derrubar todas as sessões ativas**: trocar a `TASKFLOW_SECRET_KEY` no `.env` e recriar o container. O cookie de sessão do Flask é assinado com essa chave; ao trocá-la, todos os cookies emitidos deixam de valer.
3. Revisar o que a conta fez no período (passo 4 da Fase 2).

### Recuperação

1. Confirmar que `/login` responde normalmente.
2. Monitorar a query de detecção por 24 horas (no laboratório, 15 minutos).
3. Remover o bloqueio quando o ataque cessar, ou mantê-lo se o IP for claramente malicioso:
   ```bash
   sudo iptables -D DOCKER-USER -s <IP_ATACANTE> -p tcp --dport 5000 -j DROP
   ```

## Fase 4 — Atividade Pós-Incidente

| # | Lacuna encontrada | Ação proposta |
|---|---|---|
| 1 | Login **sem limite de tentativas**: 21 tentativas em cerca de 6 segundos e 120 tentativas em menos de 3 minutos foram processadas (A07). | Rate limiting por IP e por usuário (ex.: Flask-Limiter) e bloqueio temporário após N falhas. |
| 2 | A detecção depende de alguém olhar o Grafana; a contenção levou cerca de 3 minutos após o disparo. | Regra de alerta no Grafana (`> 10` em 5 min) com notificação. |
| 3 | Atrás de proxy ou load balancer, `remote_addr` passa a ser o IP do proxy. | Configurar `ProxyFix` / `X-Forwarded-For` confiável antes de produção. |
| 4 | Conta administrativa com nome previsível (`admin`). | MFA para contas administrativas e username não óbvio. |
| 5 | Bloqueio manual por `iptables` não sobrevive a reinício e não escala. | Automatizar o bloqueio (ex.: fail2ban lendo os mesmos logs) ou aplicar no WAF/proxy. |

---

## Registro do exercício — 27 e 28/10/2026

Horários em BRT (UTC−3). Nos logs, o `timestamp` está em UTC (+3 h).

### Ataque 1 — força bruta a partir da VM

| Horário (BRT) | Evento |
|---|---|
| 23:45:46 | Login **com sucesso** de `admin` a partir de `192.168.15.110` (analista, login legítimo) |
| 23:46:46 – 23:47:26 | 4 falhas de login de `192.168.15.110` (testes manuais do analista) |
| 23:50:06 – 23:50:12 | **21 falhas em cerca de 6 s** de `172.17.0.1` contra `admin` (laço de força bruta executado na VM) |
| 23:50 | Detecção: **21** para `172.17.0.1`, acima do limiar de 10 → **runbook disparado**. O IP do analista ficou em 4, abaixo do limiar. |
| 23:50 | Escopo: única conta alvo `admin` (de 4 para 25 falhas em 15 min) |
| 23:50 | Comprometimento: um único sucesso na última hora, às 23:45:46, de `192.168.15.110`, **antes** do ataque. **Nenhum sucesso de `172.17.0.1`** → tentativa sem sucesso, severidade **Média**, erradicação não necessária. |

* **Eventos do ataque força bruta a partir da VM**
<img width="1600" height="863" alt="brute-force-login" src="https://github.com/user-attachments/assets/3faeffc3-e5a1-4a3e-a839-e6d6dc5524b5" />

* **Eventos do ataque força bruta de 5min**
<img width="1600" height="868" alt="brute-force-login-5minutes" src="https://github.com/user-attachments/assets/f4a48f20-6c23-49c4-ae1b-be7391a7ae68" />


### Ataque 2 — contenção a partir do Mac

| Horário (BRT) | Evento |
|---|---|
| 00:07:01 – 00:07:29 | 1ª rajada: 40 falhas de `192.168.15.110` contra `admin` (respostas `HTTP 200`) |
| 00:07:08 | Detecção: na 11ª falha o IP cruza o limiar de 10 em 5 min → **runbook disparado** |
| 00:08:11 – 00:09:54 | 2ª e 3ª rajadas: mais 80 falhas; a janela de 5 min chega a **120 falhas** |
| entre 00:09:54 e 00:10:29 | Contenção: `iptables -I DOCKER-USER -s 192.168.15.110 -p tcp --dport 5000 -j DROP` |
| 00:10:29 e 00:11:58 | Novas rajadas do atacante: todas as tentativas com `HTTP 000` (timeout) e **nenhum log novo** do IP no Loki — contenção confirmada |
| [HH:MM:SS] | Recuperação: regra removida e acesso ao `/login` restabelecido |

Total de falhas de `192.168.15.110` antes do bloqueio: **120** (mais 4 testes manuais às 23:46–23:47).
Nenhum login com sucesso do IP durante o ataque → severidade **Média**, erradicação não necessária.

* **Eventos de contenção a partir do Mac**

<img width="1600" height="882" alt="brute-force-login-macbook" src="https://github.com/user-attachments/assets/f4e5e4af-2300-4044-9edf-97194a79a623" />

* **Gráfico runbook acima do limiar**

<img width="1580" height="640" alt="brute-force-login-grafana" src="https://github.com/user-attachments/assets/78f325b6-e419-4db5-8758-b88e6b478829" />

* **Gráfico login com sucesso**

<img width="1593" height="596" alt="brute-force-login-onlylogin" src="https://github.com/user-attachments/assets/5efa93ed-c63c-43af-9e87-4ad7e7373763" />


### Verificação de higiene dos logs

Export dos 145 registros de `login_attempt` do período: todos com `request_id`, nenhuma ocorrência de senha, cookie ou token.
