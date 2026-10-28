"""
TaskFlow - Aplicacao de exemplo da disciplina DevSecOps (versao CORRIGIDA).

Vulnerabilidades da linha de base e como foram corrigidas:
  1. SQL Injection (login e busca)  -> consultas parametrizadas ("?").
  2. XSS armazenado                 -> HTML em templates Jinja2 (autoescape).
  3. SECRET_KEY hardcoded           -> lida de TASKFLOW_SECRET_KEY (ambiente/.env).
  4. Senhas em texto puro           -> hash com salt (werkzeug.security); senha
                                       inicial do admin vem de TASKFLOW_ADMIN_PASSWORD.
  5. Endpoint /debug/info exposto   -> removido (vazava a SECRET_KEY).
  6. debug=True e host 0.0.0.0      -> debug via FLASK_DEBUG (desligado por padrao);
                                       em producao roda via gunicorn.
  7. Cabecalhos de seguranca        -> CSP, X-Frame-Options, nosniff etc. (Modulo 4).
  8. Observabilidade (Modulo 6)     -> logs estruturados em JSON com request_id e
                                       eventos de seguranca, SEM dados sensiveis.
"""

import json
import logging
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

# Carrega variaveis do arquivo .env (apenas desenvolvimento local).
# O .env esta no .gitignore e NUNCA deve ser commitado.
load_dotenv()


# =============================================================================
# Logging estruturado em JSON (Modulo 6)
# =============================================================================
# Cada evento vira UMA linha JSON (JSON Lines). O Promtail le o arquivo e envia
# ao Loki; no Grafana os campos viram filtros (| json | result="failure").
#
# REGRA: nunca logar senha, cookie, token, SECRET_KEY, request.form inteiro,
# conteudo de tarefas ou termo de busca. So metadados necessarios a investigacao.
_CAMPOS_PADRAO_DO_RECORD = set(
    logging.LogRecord("", 0, "", 0, "", None, None).__dict__
) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """Formata cada LogRecord como uma linha JSON."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Campos de negocio passados via extra={...} (event, request_id, ip...).
        for chave, valor in record.__dict__.items():
            if chave not in _CAMPOS_PADRAO_DO_RECORD and chave not in entry:
                entry[chave] = valor
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        # json.dumps escapa quebras de linha: um atacante nao consegue
        # "forjar" uma linha de log nova (log injection).
        return json.dumps(entry, ensure_ascii=False, default=str)


def configurar_logging() -> logging.Logger:
    """Logger 'taskflow': JSON no stdout e, se possivel, no arquivo lido pelo Promtail."""
    logger = logging.getLogger("taskflow")
    if logger.handlers:  # evita handlers duplicados se o modulo for reimportado
        return logger
    logger.setLevel(os.environ.get("TASKFLOW_LOG_LEVEL", "INFO").upper())
    logger.propagate = False

    formatter = JsonFormatter()

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    log_file = os.environ.get("TASKFLOW_LOG_FILE", "logs/taskflow.log")
    if log_file:
        try:
            os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError as exc:
            # Ex.: container --read-only sem volume de logs (pipeline do DAST).
            # A app continua funcionando e loga apenas no stdout.
            logger.warning(
                "arquivo de log indisponivel; usando apenas stdout",
                extra={"event": "log_file_unavailable", "log_file": log_file, "error": str(exc)},
            )
    return logger


logger = configurar_logging()

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

# Cookie de sessao inacessivel via JavaScript e nao enviado em requisicoes
# cross-site (mitiga roubo de sessao via XSS e CSRF).
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Caminho do banco configuravel: no container aponta para /app/data (unica
# pasta gravavel pelo usuario nao-root). Localmente continua "taskflow.db".
DATABASE = os.environ.get("TASKFLOW_DATABASE", "taskflow.db")

# Cabecalhos de seguranca aplicados a TODAS as respostas.
# ANTES: o ZAP Baseline apontou 10020, 10021, 10038, 10063 e 90004
#        (cabecalhos ausentes - OWASP A02:2025 Security Misconfiguration).
# AGORA: definidos aqui uma unica vez e aplicados via after_request.
SECURITY_HEADERS = {
    # CSP: so carrega recursos da propria origem; proibe ser embutido em
    # iframe (clickjacking), plugins (object) e envio de formularios para
    # outros dominios. Sem 'unsafe-inline': scripts/estilos inline sao
    # bloqueados, uma segunda barreira caso um XSS escape do autoescape.
    "Content-Security-Policy": (
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'; "
        "base-uri 'self'; object-src 'none'"
    ),
    "X-Frame-Options": "DENY",  # clickjacking em navegadores antigos
    "X-Content-Type-Options": "nosniff",  # impede MIME sniffing
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@app.after_request
def set_security_headers(response):
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response


# =============================================================================
# request_id por requisicao (correlacao de eventos no Grafana/Loki)
# =============================================================================
@app.before_request
def iniciar_requisicao():
    g.request_id = str(uuid.uuid4())
    g.start_time = time.perf_counter()


@app.after_request
def registrar_requisicao(response):
    response.headers["X-Request-ID"] = g.get("request_id", "")
    if not request.path.startswith("/static/"):  # CSS nao interessa a investigacao
        duracao_ms = round((time.perf_counter() - g.get("start_time", time.perf_counter())) * 1000, 2)
        logger.info(
            "requisicao finalizada",
            extra={
                "event": "http_request",
                "request_id": g.get("request_id"),
                "method": request.method,
                "path": request.path,  # sem query string: nao vaza o termo de busca
                "status_code": response.status_code,
                "duration_ms": duracao_ms,
                "ip": request.remote_addr,
                "user": session.get("username"),
            },
        )
    return response


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
    #        INSERT OR IGNORE: o gunicorn sobe varios workers e cada um roda
    #        init_db() ao importar o app. Com o banco vazio, dois workers
    #        tentavam criar o admin ao mesmo tempo (UNIQUE constraint failed)
    #        e o container nao subia. Agora a criacao e idempotente.
    admin_password = os.environ.get("TASKFLOW_ADMIN_PASSWORD")
    if admin_password:
        db.execute(
            "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
            ("admin", generate_password_hash(admin_password)),
        )
        db.commit()


# init_db() roda na importacao do modulo, para funcionar tambem com o
# gunicorn (que importa o app e nunca executa o bloco __main__).
with app.app_context():
    init_db()
logger.info("aplicacao TaskFlow iniciada", extra={"event": "app_startup"})


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
            # Log de sucesso: username + IP. NUNCA a senha.
            logger.info(
                "login bem-sucedido",
                extra={
                    "event": "login_attempt",
                    "result": "success",
                    "username": username,
                    "ip": request.remote_addr,
                    "request_id": g.get("request_id"),
                },
            )
            return redirect(url_for("tasks"))

        error = "Usuario ou senha invalidos."
        # Log de falha: base da deteccao de forca bruta (falhas por IP).
        # NUNCA a senha, nem mascarada. Nao logamos request.form inteiro.
        logger.warning(
            "login falhou",
            extra={
                "event": "login_attempt",
                "result": "failure",
                "username": username,
                "ip": request.remote_addr,
                "request_id": g.get("request_id"),
            },
        )

    # ANTES: HTML retornado com f-string (Semgrep: directly-returned-format-string).
    # AGORA: template Jinja2 com autoescape.
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    logger.info(
        "logout realizado",
        extra={
            "event": "logout",
            "username": session.get("username"),
            "ip": request.remote_addr,
            "request_id": g.get("request_id"),
        },
    )
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

    # Listagem: registra QUEM acessou e o tamanho da busca, nao o termo
    # (pode conter dado pessoal ou payload de ataque).
    logger.info(
        "lista de tarefas acessada",
        extra={
            "event": "tasks_list_accessed",
            "username": session.get("username"),
            "has_search": bool(search),
            "search_length": len(search),
            "results_count": len(rows),
            "ip": request.remote_addr,
            "request_id": g.get("request_id"),
        },
    )

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
            cur = db.execute(
                "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
                (session["user_id"], title, description),
            )
            db.commit()
            # Criacao de tarefa: metadados apenas (id e tamanhos), nunca o conteudo.
            logger.info(
                "tarefa criada",
                extra={
                    "event": "task_created",
                    "username": session.get("username"),
                    "task_id": cur.lastrowid,
                    "title_length": len(title),
                    "description_length": len(description),
                    "ip": request.remote_addr,
                    "request_id": g.get("request_id"),
                },
            )
        return redirect(url_for("tasks"))

    return render_template("new_task.html")


# ANTES: rota /debug/info publica, retornando versao do Python, plataforma
#        e a propria SECRET_KEY.
# AGORA: rota removida.


if __name__ == "__main__":
    # ANTES: app.run(host="0.0.0.0", port=5000, debug=True)
    #        -> debugger do Werkzeug (execucao remota de codigo) exposto na rede.
    # AGORA: servidor de desenvolvimento so na maquina local; debug controlado
    #        pela variavel FLASK_DEBUG e DESLIGADO por padrao.
    #        Porta 5001 para evitar conflito com o AirPlay do macOS (porta 5000).
    #        Em producao/container a app roda com gunicorn (ver Dockerfile).
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() in ("1", "true", "yes")
    app.run(host="127.0.0.1", port=5001, debug=debug_mode)
