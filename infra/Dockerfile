# ==============================================================================
# Configuração do Dockerfile com Hardening (Módulo 5)
# Objetivo: Garantir que a aplicação rode em um container seguro, sem privilégios de root,
# utilizando multi-stage build e servidor WSGI (Gunicorn) para produção.
# ==============================================================================

# STAGE 1: Build - Instala dependências em um estágio separado
FROM python:3.12-slim AS build

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# STAGE 2: Runtime - Imagem final mínima
FROM python:3.12-slim AS runtime

# Copia somente os pacotes Python já instalados do estágio de build
COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin /usr/local/bin

WORKDIR /app

# Cria um usuário e grupo dedicados, além da pasta de logs com as permissões do usuário não-root
RUN groupadd --system taskflow && \
    useradd --system --gid taskflow --home-dir /app --shell /usr/sbin/nologin taskflow && \
    mkdir -p /app/logs && \
    chown -R taskflow:taskflow /app

# Copia o código da aplicação garantindo que o usuário não-root seja o dono
COPY --chown=taskflow:taskflow . .

# Expõe a porta 5000 apenas como documentação
EXPOSE 5000

# Define o usuário não-root efetivo a partir daqui
USER taskflow

# Inicializa o banco de dados e sobe a aplicação utilizando o Gunicorn (WSGI de produção)
CMD ["sh", "-c", "python -c 'from app import app, init_db; app.app_context().push(); init_db()' && gunicorn --bind 0.0.0.0:5000 --workers 2 app:app"]

# ==============================================================================
# Resumo: Este Dockerfile implementa as correções de Hardening exigidas. A técnica de
# multi-stage build reduz a superfície de ataque removendo ferramentas de compilação.
# A criação do usuário 'taskflow' impede a execução como root (FALHA 2), e o uso do
# Gunicorn substitui o servidor vulnerável de desenvolvimento do Flask (FALHA 6).
# ==============================================================================
