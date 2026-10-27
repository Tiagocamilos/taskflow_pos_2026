# Documentando pelo menos três consultas LogQL testadas pela equipe, incluindo, obrigatoriamente, a query para contagem de falhas de login por IP.
### Documentação de Observabilidade e Consultas LogQL

## 1. Estrutura de Logs da Aplicação
A TaskFlow emite logs estruturados em formato JSON no arquivo `logs/taskflow.log`, contendo os seguintes campos fundamentais:
* `timestamp`: Data/hora em padrão ISO-8601 UTC.
* `level`: Severidade (`INFO`, `WARNING`, `ERROR`).
* `request_id`: Identificador UUID único rastreável.
* `ip`: IP de origem do cliente.
* `user`: Nome de usuário tentando a autenticação.
* `event`: Categoria do evento (`login_failure`, `login_success`, `task_created`).

## 2. Consultas LogQL Utilizadas no Grafana

<img width="1618" height="814" alt="{E38E64D3-C32F-4E2D-B0FE-825EAD7054F3}" src="https://github.com/user-attachments/assets/ba34868e-d9c8-4c1f-931e-b974ffa1278c" />

### Query
```bash
{job="taskflow"} | json | event = "login_attempt" | result = "failure" | username = "admin"
```
### Consulta 1: Contagem de Falhas de Login por IP (Detecção de Força Bruta)
```logql
sum by (ip) (count_over_time({job="taskflow"} | json | event = "login_failure" [5m]))
```
# Arquitetura e Coleta de Logs - Stack Grafana/Loki/Promtail

## 1. Fluxo de Coleta de Logs
1. **Aplicação (TaskFlow):** Emite eventos de segurança e requisições formatadas em linhas JSON planas no arquivo `logs/taskflow.log`.
2. **Promtail (Agente):** Monitora o volume montado em `/var/log/taskflow/*.log`, extrai os rótulos (`level`, `event`, `result`) do JSON e envia os dados via API HTTP para o servidor Loki.
3. **Loki (Datastore):** Armazena e indexa os logs com base nos rótulos recebidos.
4. **Grafana (Visualização):** Conecta-se ao Loki como Datasource e executa queries LogQL para dashboards e alertas.

---

## 2. Consultas LogQL Testadas

### Consulta 1: Agrupamento e contagem de falhas de login por IP de origem (OBRIGATÓRIA)
```logql
sum by (ip) (count_over_time({job="taskflow"} | json | event="login_attempt" | result="failure" [5m]))
```
### Script de força bruta
```bash
curl -s -X POST http://localhost:5000/login -d "username=admin&password=errada"
for i in {1..20}; do   curl -s -X POST http://localhost:5000/login     -d "username=admin&password=wrongpassword$i" > /dev/null;   echo "Tentativa $i enviada.";   sleep 0.2; done
```

