import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, abort, flash, g, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

DATABASE = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "memo.db"))
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128
MEMO_MAX_LENGTH = 2000
ADMIN_USERNAME = "admin"
LOGIN_LIMIT = 5
LOGIN_WINDOW_SECONDS = 300

SECRET_KEY = os.environ.get("SECRET_KEY", "")
if len(SECRET_KEY) < 32 or SECRET_KEY == "{change_secret_key}":
    raise RuntimeError("SECRET_KEY must be an unpredictable value of at least 32 characters.")

app = Flask(__name__)
trusted_hosts = [host.strip() for host in os.environ.get("TRUSTED_HOSTS", "localhost,127.0.0.1").split(",") if host.strip()]
app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=16 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=1800,
    TRUSTED_HOSTS=trusted_hosts,
)

_login_attempts = {}
_login_lock = threading.Lock()
_dummy_password_hash = generate_password_hash(secrets.token_urlsafe(24))


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE, timeout=5)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create/migrate tables and seed the configured admin once."""
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
                created_at TEXT NOT NULL
            )
        """)
        columns = {row[1] for row in db.execute("PRAGMA table_info(user)")}
        if "role" not in columns:
            db.execute("ALTER TABLE user ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        if "created_at" not in columns:
            db.execute("ALTER TABLE user ADD COLUMN created_at TEXT")
            db.execute("UPDATE user SET created_at = ? WHERE created_at IS NULL", (utc_now(),))
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS user_username_nocase ON user(username COLLATE NOCASE)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS memo (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
            )
        """)

        admin = db.execute("SELECT id, role FROM user WHERE username = ?", (ADMIN_USERNAME,)).fetchone()
        if admin is None:
            password = os.environ.get("ADMIN_PASSWORD", "")
            flag = os.environ.get("ADMIN_MEMO_CONTENT", "")
            if not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
                raise RuntimeError(f"ADMIN_PASSWORD must be {PASSWORD_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters.")
            if not re.fullmatch(r"SBOB\{[^\r\n]{1,1900}\}", flag):
                raise RuntimeError("ADMIN_MEMO_CONTENT must have the form SBOB{...}.")
            now = utc_now()
            cursor = db.execute(
                "INSERT INTO user (username, password, role, created_at) VALUES (?, ?, 'admin', ?)",
                (ADMIN_USERNAME, generate_password_hash(password), now),
            )
            db.execute(
                "INSERT INTO memo (user_id, content, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (cursor.lastrowid, flag, now, now),
            )
        elif admin["role"] != "admin":
            raise RuntimeError("Reserved username 'admin' already exists without the admin role.")
        db.commit()


@app.before_request
def load_user_and_check_csrf():
    g.current_user = None
    user_id = session.get("user_id")
    if isinstance(user_id, int):
        g.current_user = get_db().execute(
            "SELECT id, username, role FROM user WHERE id = ?", (user_id,)
        ).fetchone()
        if g.current_user is None:
            session.clear()

    if request.method == "POST":
        expected = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "")
        if not expected or not supplied or not hmac.compare_digest(expected, supplied):
            abort(400, description="Invalid CSRF token.")


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    if app.config["SESSION_COOKIE_SECURE"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.current_user is None:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.current_user is None:
            return redirect(url_for("login"))
        if g.current_user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def format_timestamp(value):
    return datetime.fromisoformat(value).astimezone().strftime("%m/%d %H:%M")


def login_key(username):
    return request.remote_addr or "unknown", username.casefold()


def login_is_limited(key):
    cutoff = time.monotonic() - LOGIN_WINDOW_SECONDS
    with _login_lock:
        attempts = [stamp for stamp in _login_attempts.get(key, []) if stamp >= cutoff]
        _login_attempts[key] = attempts
        return len(attempts) >= LOGIN_LIMIT


def record_login_failure(key):
    with _login_lock:
        _login_attempts.setdefault(key, []).append(time.monotonic())


STYLE = """<style>
:root{font-family:system-ui,-apple-system,sans-serif;color:#0d3854;background:#eaf9ff;--navy:#155f8a;--ice:#f0fcff;--blue:#3fc2f0;--orange:#ffb84d}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 15% 15%,#fff 0 3px,transparent 4px),radial-gradient(circle at 80% 25%,#fff 0 2px,transparent 3px),linear-gradient(#cdf2ff 0,#eefbff 48%,#f9fdff 100%);background-size:90px 90px,120px 120px,auto}
a{color:#087eac}.nav{display:flex;justify-content:space-between;align-items:center;gap:15px;padding:14px 24px;background:rgba(255,255,255,.9);border-bottom:3px solid #9edff3;box-shadow:0 3px 14px #0b60831c}.nav a{margin-left:14px;font-weight:700;text-decoration:none}.brand{font-size:1.25rem!important;color:var(--navy)!important;margin-left:0!important}.brand-mark{display:inline-grid;place-items:center;width:38px;height:38px;margin-right:8px;border-radius:50%;background:var(--navy);font-size:23px;vertical-align:middle}
.page{max-width:880px;min-height:calc(100vh - 165px);margin:auto;padding:32px 24px}.flash{padding:12px 15px;margin-bottom:14px;background:#fff4d8;border:1px solid #ffd277;border-radius:12px}
h1{color:var(--navy)}form{display:grid;gap:11px}.auth{max-width:390px;margin:35px auto;padding:28px;background:rgba(255,255,255,.92);border:1px solid #b9dfec;border-radius:20px;box-shadow:0 15px 40px #17648418}
input,textarea,button{font:inherit;padding:11px;border:1px solid #9bcddd;border-radius:10px}input:focus,textarea:focus{outline:3px solid #9ee5fa;border-color:#199dc9}textarea{background:#fcfeff;resize:vertical}
button{background:var(--navy);color:#fff;border:0;cursor:pointer;font-weight:700}button:hover{background:#087eac}.board{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:15px;margin-top:22px}
.card{display:block;min-height:120px;padding:17px;background:rgba(255,255,255,.94);border:1px solid #afdce9;border-radius:8px 24px 8px 24px;color:inherit;text-decoration:none;box-shadow:0 8px 20px #17648414}.card:hover{transform:translateY(-2px);border-color:var(--blue)}.memo{white-space:pre-wrap;word-break:break-word}
.hero{display:grid;grid-template-columns:190px 1fr;align-items:center;gap:38px;margin:35px 0;padding:38px;background:rgba(255,255,255,.82);border:1px solid #b9e4f1;border-radius:30px 8px 30px 8px;box-shadow:0 18px 50px #17648419}.hero h1{font-size:2.25rem;margin:0 0 10px}.hero p{font-size:1.08rem;line-height:1.7;color:#416981}.hero-actions a{display:inline-block;margin:8px 8px 0 0;padding:11px 18px;border-radius:12px;background:var(--navy);color:#fff;text-decoration:none;font-weight:700}
.penguin{position:relative;width:145px;height:180px;margin:auto;border-radius:48% 48% 45% 45%;background:var(--navy);box-shadow:inset 0 -8px 0 #0a2942,0 12px 0 -5px #bdeaf7}.penguin:before{content:"";position:absolute;left:26px;top:45px;width:93px;height:116px;border-radius:50% 50% 45% 45%;background:#fff}.penguin:after{content:"";position:absolute;left:57px;top:55px;width:31px;height:19px;background:var(--orange);clip-path:polygon(0 0,100% 50%,0 100%)}.eyes{position:absolute;z-index:2;left:43px;top:37px;width:10px;height:10px;border-radius:50%;background:#071b2c;box-shadow:48px 0 #071b2c}.feet{position:absolute;z-index:2;left:22px;bottom:-7px;width:48px;height:18px;border-radius:50%;background:var(--orange);box-shadow:55px 0 var(--orange)}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 8px 25px #17648414}th{background:var(--navy);color:#fff}th,td{text-align:left;padding:11px;border-bottom:1px solid #cce8f0}.inline{display:inline}.muted{color:#5e7d8e;font-size:.85rem}
.site-footer{text-align:center;padding:19px;background:#d2f1fa;border-top:1px solid #a8ddea;color:#547687}
@media(max-width:650px){.nav{align-items:flex-start;padding:12px}.hero{grid-template-columns:1fr;text-align:center;padding:28px 20px}.penguin{transform:scale(.85)}.page{padding:20px 14px}.nav div{display:flex;align-items:center;flex-wrap:wrap;justify-content:flex-end}}
</style>"""
HEADER = """<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>🐧 Memo Vault</title>""" + STYLE + """</head><body><nav class="nav"><a class="brand" href="{{ url_for('index') }}"><span class="brand-mark">🐧</span>Memo Vault</a><div>
{% if g.current_user %}<span>{{ g.current_user['username'] }}</span>{% if g.current_user['role'] == 'admin' %}<a href="{{ url_for('admin_users') }}">회원 관리</a>{% endif %}
<form class="inline" method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button>로그아웃</button></form>
{% else %}<a href="{{ url_for('login') }}">로그인</a><a href="{{ url_for('signup') }}">회원가입</a>{% endif %}</div></nav><main class="page">
{% for message in get_flashed_messages() %}<div class="flash">{{ message }}</div>{% endfor %}"""
FOOTER = """</main><footer class="site-footer">🐧 Memo · 간단한 개인 메모장</footer></body></html>"""


def render_page(content, **context):
    return render_template_string(HEADER + content + FOOTER, **context)


@app.get("/")
def index():
    if g.current_user is None:
        return render_page("""<section class="hero"><div class="penguin" aria-hidden="true"><span class="eyes"></span><span class="feet"></span></div>
        <div><h1>🐧 Memo</h1><p>필요한 내용을 간편하게 기록하고 관리하세요.</p>
        <div class="hero-actions"><a href="{{ url_for('login') }}">로그인</a><a href="{{ url_for('signup') }}">회원가입</a></div></div></section>""")
    rows = get_db().execute(
        "SELECT id, content, updated_at FROM memo WHERE user_id = ? ORDER BY updated_at DESC", (g.current_user["id"],)
    ).fetchall()
    memos = [{"id": row["id"], "preview": row["content"][:80] + ("…" if len(row["content"]) > 80 else ""),
              "updated_at": format_timestamp(row["updated_at"])} for row in rows]
    return render_page("""<h1>내 메모</h1><form method="post" action="{{ url_for('new_memo') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><textarea name="content" maxlength="{{ max_len }}" required></textarea><button>추가</button></form>
    <div class="board">{% for memo in memos %}<a class="card" href="{{ url_for('memo_detail', memo_id=memo.id) }}"><div class="memo">{{ memo.preview }}</div>
    <div class="muted">{{ memo.updated_at }}</div></a>{% else %}<p>메모가 없습니다.</p>{% endfor %}</div>""", memos=memos, max_len=MEMO_MAX_LENGTH)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if g.current_user is not None:
        return redirect(url_for("index"))
    username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("password_confirm", "")
        if not USERNAME_PATTERN.fullmatch(username) or username.casefold() == ADMIN_USERNAME:
            flash("아이디는 영문, 숫자, 밑줄 3~20자로 입력하세요.")
        elif not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
            flash(f"비밀번호는 {PASSWORD_MIN_LENGTH}~{PASSWORD_MAX_LENGTH}자로 입력하세요.")
        elif password != confirm:
            flash("비밀번호가 일치하지 않습니다.")
        else:
            try:
                get_db().execute("INSERT INTO user (username,password,role,created_at) VALUES (?,?,'user',?)",
                                 (username, generate_password_hash(password), utc_now()))
                get_db().commit()
                flash("가입되었습니다. 로그인해 주세요.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("이미 사용 중인 아이디입니다.")
    return render_page("""<h1>회원가입</h1><form class="auth" method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <label>아이디</label><input name="username" value="{{ username }}" maxlength="20" autocomplete="username" required>
    <label>비밀번호 (12자 이상)</label><input type="password" name="password" maxlength="128" autocomplete="new-password" required>
    <label>비밀번호 확인</label><input type="password" name="password_confirm" maxlength="128" autocomplete="new-password" required><button>가입</button></form>""", username=username)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.current_user is not None:
        return redirect(url_for("index"))
    username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        key = login_key(username)
        if login_is_limited(key):
            abort(429)
        user = get_db().execute("SELECT id,username,password FROM user WHERE username = ?", (username,)).fetchone()
        valid = check_password_hash(user["password"] if user else _dummy_password_hash, password)
        if not user or not valid:
            record_login_failure(key)
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")
        else:
            with _login_lock:
                _login_attempts.pop(key, None)
            session.clear()
            session.update(user_id=user["id"], csrf_token=secrets.token_urlsafe(32))
            session.permanent = True
            return redirect(url_for("index"))
    return render_page("""<h1>로그인</h1><form class="auth" method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <label>아이디</label><input name="username" value="{{ username }}" maxlength="20" autocomplete="username" required>
    <label>비밀번호</label><input type="password" name="password" maxlength="128" autocomplete="current-password" required><button>로그인</button></form>""", username=username)


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/memos/<int:memo_id>")
@login_required
def memo_detail(memo_id):
    memo = get_db().execute("SELECT * FROM memo WHERE id = ? AND user_id = ?", (memo_id, g.current_user["id"])).fetchone()
    if memo is None:
        abort(404)
    return render_page("""<h1>메모</h1><form method="post" action="{{ url_for('edit_memo', memo_id=memo.id) }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><textarea name="content" maxlength="{{ max_len }}" rows="12" required>{{ memo.content }}</textarea>
    <div class="muted">생성 {{ created }} · 수정 {{ updated }}</div><button>저장</button>
    <button formaction="{{ url_for('delete_memo', memo_id=memo.id) }}">삭제</button></form>""",
    memo=memo, max_len=MEMO_MAX_LENGTH, created=format_timestamp(memo["created_at"]), updated=format_timestamp(memo["updated_at"]))


def memo_content():
    content = request.form.get("content", "").strip()
    if not content or len(content) > MEMO_MAX_LENGTH:
        abort(400)
    return content


@app.post("/memos/new")
@login_required
def new_memo():
    now = utc_now()
    get_db().execute("INSERT INTO memo (user_id,content,created_at,updated_at) VALUES (?,?,?,?)",
                     (g.current_user["id"], memo_content(), now, now))
    get_db().commit()
    return redirect(url_for("index"))


@app.post("/memos/<int:memo_id>/edit")
@login_required
def edit_memo(memo_id):
    cursor = get_db().execute("UPDATE memo SET content=?,updated_at=? WHERE id=? AND user_id=?",
                              (memo_content(), utc_now(), memo_id, g.current_user["id"]))
    get_db().commit()
    if cursor.rowcount != 1:
        abort(404)
    return redirect(url_for("memo_detail", memo_id=memo_id))


@app.post("/memos/<int:memo_id>/delete")
@login_required
def delete_memo(memo_id):
    cursor = get_db().execute("DELETE FROM memo WHERE id=? AND user_id=?", (memo_id, g.current_user["id"]))
    get_db().commit()
    if cursor.rowcount != 1:
        abort(404)
    return redirect(url_for("index"))


@app.get("/admin/users")
@admin_required
def admin_users():
    users = get_db().execute("""SELECT u.id,u.username,u.role,u.created_at,COUNT(m.id) memo_count
        FROM user u LEFT JOIN memo m ON m.user_id=u.id GROUP BY u.id ORDER BY u.id""").fetchall()
    return render_page("""<h1>전체 회원 목록</h1><table><thead><tr><th>ID</th><th>아이디</th><th>역할</th><th>가입일</th><th>메모 수</th></tr></thead>
    <tbody>{% for user in users %}<tr><td>{{ user.id }}</td><td>{{ user.username }}</td><td>{{ user.role }}</td>
    <td>{{ user.created_at }}</td><td>{{ user.memo_count }}</td></tr>{% endfor %}</tbody></table>""", users=users)


if __name__ == "__main__":
    init_db()
    from waitress import serve

    serve(
        app,
        host=os.environ.get("BIND_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_PORT", "5000")),
        clear_untrusted_proxy_headers=True,
    )
