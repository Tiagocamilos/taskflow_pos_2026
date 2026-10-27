# Detalhando as quatro fases de resposta a incidentes do NIST SP 800-61 e registrando evidências da simulação do ataque de força bruta detectado no Grafana.

## Fase 1: Preparação
* Configuração do Logger em JSON no `app.py` registrando os campos `ip`, `username` e `result`.
* Dashboard no Grafana monitorando a taxa de falhas de autenticação.
* Limiar de Alerta: Mais de 5 falhas de login originadas do mesmo IP em um janela de 5 minutos.

## Fase 2: Detecção e Análise
* **Gatilho de Alerta:** Disparo de notificação por pico atípico no painel de segurança.
* **Consulta de Investigação (Grafana LogQL):**
  ```
  sum by (ip) (count_over_time({job="taskflow"} | json | event="login_attempt" | result="failure" [5m]))
  ```

  Análise de Impacto: Identificação do IP atacante e verificação se houve algum evento subsequente com result="success" para o mesmo usuário.

Fase 3: Contenção, Erradicação e Recuperação

    Contenção: Bloqueio imediato do IP atacante no Firewall/WAF (ex.: sudo ufw deny from <IP_ATACANTE>).

    Erradicação: Invalidação de todas as sessões ativas do usuário alvo do ataque.

    Recuperação: Solicitação de redefinição de senha para a conta afetada.

Fase 4: Atividades Pós-Incidente

    Registro dos indicadores de comprometimento (IoCs) no relatório de incidentes.

    Ajuste no middleware da aplicação para implementar Limitação de Taxa (Rate Limiting) via Flask-Limiter (ex.: máximo de 5 tentativas por minuto por IP na rota /login).
