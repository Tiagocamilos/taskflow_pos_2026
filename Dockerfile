# Dockerfile HARDENED - corrige as seis falhas do Dockerfile original.

# CORRIGIDO (FALHA 1): tag fixada e imagem slim (menos pacotes de SO,
# menos CVEs), em vez de "latest". Build multi-stage: o estagio final
# nao carrega cache nem ferramentas de instalacao.
FROM python:3.12-slim AS build

WORKDIR /app

COPY requirements.txt .

# CORRIGIDO (FALHA 3): versoes fixadas no requirements.txt (auditadas pelo
# pip-audit no sca.yml) e --no-cache-dir para nao deixar cache na camada.
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim AS runtime

# Banco aponta para /app/data: unica pasta gravavel (volume no docker run).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TASKFLOW_DATABASE=/app/data/taskflow.db

COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin /usr/local/bin

WORKDIR /app

# CORRIGIDO (FALHA 2): usuario e grupo dedicados, sem privilegios de root.
# So a pasta data/ (banco SQLite) e gravavel por ele.
RUN groupadd --system taskflow && \
    useradd --system --gid taskflow --no-create-home --shell /usr/sbin/nologin taskflow && \
    mkdir -p /app/data && \
    chown taskflow:taskflow /app/data

# ANTES: "COPY --chown=taskflow:taskflow . ." levava .env, .git, codigo/ e o
#        banco local para a imagem, e deixava o codigo alteravel pela app.
# AGORA: copia SO o necessario; arquivos ficam do root (somente leitura p/ app).
COPY app.py .
COPY templates/ templates/

# CORRIGIDO (FALHA 4): nenhum segredo em ENV/ARG. TASKFLOW_SECRET_KEY e
# TASKFLOW_ADMIN_PASSWORD sao injetadas em tempo de execucao (docker run -e).

# CORRIGIDO (FALHA 5): EXPOSE apenas documenta a porta do gunicorn; o
# servidor de desenvolvimento do Flask nao e mais usado.
EXPOSE 5000

USER taskflow

# CORRIGIDO (FALHA 6): gunicorn (WSGI de producao) no lugar de "python app.py".
# Sem debug: o bloco __main__ do app.py nao e executado. O init_db() roda
# na importacao do app.py, entao nao precisa de comando extra.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
