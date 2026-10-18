"""
TaskFlow - Aplicacao de exemplo da disciplina DevSecOps (versao CORRIGIDA).

Vulnerabilidades da linha de base e como foram corrigidas:
  1. SQL Injection (login e busca)  -> consultas parametrizadas ("?").
  2. XSS armazenado                 -> HTML em templates Jinja2 (autoescape).
  3. SECRET_KEY hardcoded           -> lida de TASKFLOW_SECRET_KEY (ambiente/.env).
  4. Senhas em texto puro           -> hash com salt (werkzeug.security); senha
                                       inicial do admin vem de TASKFLOW_ADMIN_PASSWORD.
  5. Endpoint /debug/info exposto   -> removido (vazava a SECRET_KEY).
  6. debug=True e host 0.0.0.0      -> removidos; em producao roda via gunicorn.
  (Dependencias com CVE sao tratadas no requirements.txt + pip-audit/Dependabot.)
"""

import os
import sqlite3

from dotenv import load_dotenv
from flask import Flask, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

# Carrega variaveis do arquivo .env (apenas desenvolvimento local).
# O .env esta no .gitignore e NUNCA deve ser commitado.
load_dotenv()

app = Flask(__name__)

# ANTES: SECRET_KEY com valor fixo no codigo (achado de SAST/secret scanning).
# AGORA: lida do ambiente; sem ela a app nao sobe (fail fast).
_secret_key = os.environ.get("TASKFLOW_SECRET_KEY")
if not _secret_key:
    raise RuntimeError(
        "Variavel de ambiente TASKFLOW_SECRET_KEY nao foi definida. "
        "Configure-a antes de iniciar a aplicacao "
        "(ex: export TASKFLOW_SECRET_KEY='valor-aleatorio-e-longo')."
    )
app.config["SECRET_KEY"] = _secret_key

# AGORA: cookie de sessao inacessivel via JavaScript e nao enviado em
# requisicoes cross-site.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Caminho do banco configuravel: no container aponta para /app/data (unica
# pasta gravavel pelo usuario nao-root). Localmente continua "taskflow.db".
DATABASE = os.environ.get("TASKFLOW_DATABASE", "taskflow.db")


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            done INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    db.commit()

    # ANTES: usuarios criados com senha em texto puro ("admin123") no codigo
    #        e gravada sem hash no banco.
    # AGORA: a senha inicial vem do ambiente e e gravada como HASH (com salt).
    #        Se TASKFLOW_ADMIN_PASSWORD nao existir, nenhum usuario e criado.
    admin_password = os.environ.get("TASKFLOW_ADMIN_PASSWORD")
    cur = db.execute("SELECT COUNT(*) AS total FROM users")
    if cur.fetchone()["total"] == 0 and admin_password:
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", generate_password_hash(admin_password)),
        )
        db.commit()


# ANTES: init_db() so era chamado dentro do bloco __main__.
# AGORA: roda na importacao do modulo, para funcionar tambem com o gunicorn
#        (que importa o app e nunca executa o bloco __main__).
with app.app_context():
    init_db()


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("tasks"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ANTES: "... WHERE username = '" + username + "' AND password = '" ...
        #        -> SQL Injection (ex.: usuario  admin' --  entrava sem senha).
        # AGORA: query parametrizada; a senha e conferida pelo hash, fora do SQL.
        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if user and check_password_hash(user["password"], password):
            # Limpa a sessao anterior antes de autenticar (evita fixacao de sessao).
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("tasks"))
        error = "Usuario ou senha invalidos."

    # ANTES: HTML retornado com f-string (Semgrep: directly-returned-format-string).
    # AGORA: template Jinja2 com autoescape.
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/tasks", methods=["GET"])
def tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))

    search = request.args.get("q", "")
    db = get_db()

    if search:
        # ANTES: "... AND title LIKE '%" + search + "%'" -> SQL Injection.
        # AGORA: o padrao do LIKE e montado fora do SQL e passado como parametro.
        like_pattern = f"%{search}%"
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ? AND title LIKE ?",
            (session["user_id"], like_pattern),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ?", (session["user_id"],)
        ).fetchall()

    # ANTES: HTML montado com f-string -> XSS armazenado na descricao.
    # AGORA: template Jinja2 com autoescape ("<script>" vira "&lt;script&gt;").
    return render_template(
        "tasks.html",
        rows=rows,
        search=search,
        username=session["username"],
    )


@app.route("/tasks/new", methods=["GET", "POST"])
def new_task():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "")
        if title:
            db = get_db()
            db.execute(
                "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
                (session["user_id"], title, description),
            )
            db.commit()
        return redirect(url_for("tasks"))

    return render_template("new_task.html")


# ANTES: rota /debug/info publica, retornando versao do Python, plataforma
#        e a propria SECRET_KEY.
# AGORA: rota removida.


if __name__ == "__main__":
    # ANTES: app.run(host="0.0.0.0", port=5000, debug=True)
    #        -> debugger do Werkzeug (execucao remota de codigo) exposto na rede.
    # AGORA: servidor de desenvolvimento so na maquina local, sem debug.
    #        Porta 5001 para evitar conflito com o AirPlay do macOS (porta 5000).
    #        Em producao/container a app roda com gunicorn (ver Dockerfile).
    app.run(host="127.0.0.1", port=5001)


# =============================================================================
# RESUMO DAS CORREÇÕES E MELHORIAS DE SEGURANÇA NO APP.PY
# =============================================================================

# Remediacao de SQL Injection (Consultas Parametrizadas)
# - O que mudou: Uso do placeholder "?" nas consultas no login e na busca por tarefas.
# - Por quê: Elimina a concatenacao de strings enviadas por usuarios, garantindo que a entrada do usuario seja tratada estritamente como dado e nao executada como instrucao SQL.

# Mitigacao de XSS e Injecao de HTML (Templates Jinja2)
# - O que mudou: Substituicao de HTML formatado diretamente no codigo por `render_template` com arquivos `.html`.
# - Por quê: O Jinja2 ativa por padrao o mecanismo de autoescape, convertendo caracteres perigosos (como `<script>`) em entidades HTML seguras (`&lt;script&gt;`), saneando as descricoes de tarefas.

# Remocao de Segredos Hardcoded (TASKFLOW_SECRET_KEY e TASKFLOW_ADMIN_PASSWORD)
# - O que mudou: Leitura obrigatoria da `SECRET_KEY` e da senha do administrador a partir de variaveis de ambiente (via python-dotenv ou runtime).
# - Por quê: Previne o vazamento de chaves secretas e senhas padrao no historico de commits do Git e ativa o comportamento de fail-fast caso a chave nao esteja definida.

# Armazenamento Seguro de Credenciais (Hash de Senha)
# - O que mudou: Utilizacao de `generate_password_hash` e `check_password_hash` da biblioteca Werkzeug.
# - Por quê: Evita o armazenamento de senhas em texto puro no banco de dados SQLite, aplicando algoritmo de hashing forte com inclusao automatica de salt.

# Remocao de Endpoint Exposto (/debug/info)
# - O que mudou: Exclusao completa do endpoint `/debug/info`.
# - Por quê: Impede a exposicao sensivel de informacoes do ambiente e o vazamento do token de sessao/SECRET_KEY.

# Hardening no Servidor de Desenvolvimento e Coockie de Sessao
# - O que mudou: Desativacao da flag `debug=True`, mudanca do host para `127.0.0.1` e adicao de `SESSION_COOKIE_HTTPONLY = True` e `SESSION_COOKIE_SAMESITE = 'Lax'`.
# - Por quê: Bloqueia a execucao remota de codigo pelo debugger do Werkzeug na rede local e protege o cookie de sessao contra ataques do tipo CSRF e leitura via JavaScript malicioso.
vv
