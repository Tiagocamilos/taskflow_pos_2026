# =============================================================================
# CI - TaskFlow
# Esteira basica: instala dependencias e roda lint em todo PR para a main.
# O job "Build e Lint" e um required status check: se falhar, o merge e bloqueado.
# =============================================================================

name: CI - TaskFlow

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch: # permite rodar manualmente pela aba Actions

# ANTES: sem "permissions" -> o GITHUB_TOKEN recebia as permissoes padrao (amplas).
# AGORA: minimo privilegio. O job so precisa ler o codigo.
permissions:
  contents: read

# ANTES: versao do Python fixa no meio do step ("3.10") e diferente em cada workflow.
# AGORA: versoes centralizadas em env (boa pratica de Pipeline as Code).
#         3.12 = mesma versao da imagem do Dockerfile, CI testa o que vai para producao.
env:
  PYTHON_VERSION: "3.12"
  RUFF_VERSION: "0.6.9"

jobs:
  build-e-lint:
    # Nome exibido no PR e usado na branch protection (required check).
    name: Build e Lint
    runs-on: ubuntu-latest
    steps:
      # ANTES: actions/checkout@v4 (tag mutavel, pode ser movida para codigo malicioso).
      # AGORA: pin pelo SHA do commit (imutavel). O comentario indica a versao
      #         e permite que o Dependabot atualize o pin.
      - name: Checkout do codigo
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4

      # ANTES: actions/setup-python@v5 (tag mutavel).
      # AGORA: pin por SHA + cache do pip para acelerar as execucoes.
      - name: Configurar Python ${{ env.PYTHON_VERSION }}
        uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
        with:
          python-version: ${{ env.PYTHON_VERSION }}
          cache: pip

      # AGORA: ruff instalado com versao fixa (build reprodutivel).
      - name: Instalar dependencias
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install "ruff==${{ env.RUFF_VERSION }}"

      # ANTES: "python -m py_compile app.py" -> so checava sintaxe
      #         (nao pegou, por exemplo, o "import os" que faltava).
      # AGORA: ruff (exigido pela atividade) -> detecta imports faltando,
      #         nomes indefinidos e codigo morto. Se falhar, o PR fica vermelho.
      - name: Lint com ruff
        run: ruff check .


# Inclusão do permissions: contents: read
# - O que mudou: Restringiu o token de execução do GitHub (GITHUB_TOKEN) apenas para leitura de código.
# - Por quê: Aplica o princípio de mínimo privilégio para evitar que, em caso de comprometimento do pipeline, um atacante consiga alterar arquivos no repositório.

# Centralização das versões em env (PYTHON_VERSION e RUFF_VERSION)
# - O que mudou: As versões foram definidas como variáveis globais no topo do arquivo em vez de ficarem espalhadas nos steps.
# - Por quê: Garante padronização e reprodutibilidade, alinhando a versão do Python no CI (3.12) com a mesma utilizada no Dockerfile e facilitando manutenções futuras.

# Fixação das Actions por Commit SHA (actions/checkout e actions/setup-python)
# - O que mudou: Substituiu as tags mutáveis (ex: @v4, @v5) pelo hash SHA exato do commit (ex: @11d5960...).
# - Por quê: Protege a esteira contra ataques na cadeia de suprimentos (Supply Chain Attacks), garantindo que o código da action não seja alterado de forma maliciosa na origem.

# Adição do Cache do Pip (cache: pip)
# - O que mudou: Ativou a opção de cache na action do Python.
# - Por quê: Reutiliza os pacotes instalados em execuções anteriores, acelerando o tempo de execução da esteira.

# Substituição do py_compile pelo ruff check .
# - O que mudou: Substituiu a simples checagem de sintaxe do Python pelo analisador estático (linter) Ruff com versão fixada (0.6.9).
# - Por quê: Cria um quality gate efetivo, capaz de detectar variáveis não utilizadas, erro de pacotes faltantes (ex: import os), nomes indefinidos e más práticas que o compilador padrão deixava passar.
