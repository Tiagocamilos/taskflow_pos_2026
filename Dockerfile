# Dockerfile HARDENED - corrige as seis falhas do Dockerfile original.

# CORRIGIDO (FALHA 1): tag fixada e imagem minima (alpine: menos pacotes de
# SO, menos CVEs), em vez de "latest". Build multi-stage: o estagio final
# nao carrega cache nem ferramentas de instalacao.
FROM python:3.12-alpine AS build

WORKDIR /app

COPY requirements.txt .

# CORRIGIDO (FALHA 3): versoes fixadas no requirements.txt (auditadas pelo
# pip-audit no sca.yml) e --no-cache-dir para nao deixar cache na camada.
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-alpine AS runtime

# Banco aponta para /app/data: unica pasta gravavel (volume no docker run).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    TASKFLOW_DATABASE=/app/data/taskflow.db \
    TASKFLOW_LOG_FILE=/app/logs/taskflow.log

COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin /usr/local/bin

WORKDIR /app

# CORRIGIDO (FALHA 2): usuario e grupo dedicados, sem privilegios de root.
# So a pasta data/ (banco SQLite) e gravavel por ele.
RUN addgroup -S taskflow && \
    adduser -S -G taskflow -H -s /sbin/nologin taskflow && \
    mkdir -p /app/data /app/logs && \
    chown taskflow:taskflow /app/data /app/logs

# Copia SO o necessario; arquivos ficam do root (somente leitura p/ app).
# static/ guarda o CSS externo exigido pela CSP (sem estilos inline).
COPY app.py .
COPY templates/ templates/
COPY static/ static/

# CORRIGIDO (FALHA 4): nenhum segredo em ENV/ARG. TASKFLOW_SECRET_KEY e
# TASKFLOW_ADMIN_PASSWORD sao injetadas em tempo de execucao (docker run -e).

# CORRIGIDO (FALHA 5): EXPOSE apenas documenta a porta do gunicorn.
EXPOSE 5000

USER taskflow

# CORRIGIDO (FALHA 6): gunicorn (WSGI de producao) no lugar de "python app.py".
# Sem debug: o bloco __main__ do app.py nao e executado.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
