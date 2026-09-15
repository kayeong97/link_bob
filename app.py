import os
import re
import sqlite3
from datetime import datetime
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    g,
    get_flashed_messages,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "memo.db")

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")
PASSWORD_MIN_LENGTH = 4
PASSWORD_MAX_LENGTH = 128
MEMO_MAX_LENGTH = 2000
MEMO_PREVIEW_LENGTH = 80
MEMO_COLORS = ["#eef1f8", "#eef6f1", "#f7f1ea", "#f1eef8"]

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        ".env 파일에 SECRET_KEY가 설정되어 있지 않습니다. .env.example을 참고해 값을 추가해주세요."
    )

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS memo (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES user (id)
            )
            """
        )
        db.commit()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("username"):
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def format_timestamp(iso_str):
    return datetime.fromisoformat(iso_str).strftime("%m/%d %H:%M")


def make_preview(content):
    if len(content) <= MEMO_PREVIEW_LENGTH:
        return content
    return content[:MEMO_PREVIEW_LENGTH] + "…"


HEADER = """
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>메모장</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@400;500;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #fafafa;
    --surface: #ffffff;
    --border: #e2e5e9;
    --ink: #2b2f36;
    --ink-muted: #6b7280;
    --accent: #4f6ef7;
    --accent-hover: #3d59d6;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    font-family: 'Noto Sans KR', system-ui, sans-serif;
    color: var(--ink);
    background: var(--bg);
  }
  a { color: var(--accent); }
  .nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    padding: 16px 24px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }
  .nav .brand { font-size: 1.2rem; font-weight: 700; text-decoration: none; color: var(--ink); }
  .nav .links { display: flex; align-items: center; gap: 16px; font-size: 0.9rem; }
  .nav .links span { color: var(--ink-muted); }
  .nav .links a { text-decoration: none; font-weight: 500; }
  .nav .links a:hover { color: var(--accent-hover); }
  .flash-wrap { max-width: 720px; margin: 16px auto 0; padding: 0 24px; }
  .flash {
    background: #eef1fd;
    border: 1px solid #c9d3fb;
    color: var(--ink);
    padding: 10px 14px;
    border-radius: 8px;
    margin-bottom: 8px;
    font-size: 0.9rem;
  }
  .page { max-width: 720px; margin: 0 auto; padding: 24px; }
  h1 { font-size: 1.5rem; margin-top: 0; }
  .intro { text-align: center; padding: 60px 20px; }
  .intro p { color: var(--ink-muted); }
  form.auth-form {
    display: flex;
    flex-direction: column;
    gap: 10px;
    max-width: 320px;
    margin: 40px auto;
    background: var(--surface);
    padding: 24px;
    border-radius: 10px;
    border: 1px solid var(--border);
  }
  label { font-size: 0.85rem; font-weight: 500; color: var(--ink-muted); }
  input[type="text"], input[type="password"], textarea {
    width: 100%;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 10px;
    font-family: inherit;
    font-size: 0.95rem;
    background: var(--surface);
    color: var(--ink);
  }
  input[type="text"]:focus, input[type="password"]:focus, textarea:focus {
    outline: none;
    border-color: var(--accent);
  }
  button, input[type="submit"] {
    font-family: inherit;
    font-size: 0.9rem;
    background: var(--accent);
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    cursor: pointer;
    font-weight: 500;
    color: #fff;
  }
  button:hover, input[type="submit"]:hover { background: var(--accent-hover); }
  button.secondary {
    background: transparent;
    color: var(--ink-muted);
    border: 1px solid var(--border);
  }
  button.secondary:hover { background: #f2f3f5; color: var(--ink); }
  .new-memo-form { display: flex; gap: 10px; margin: 20px 0; align-items: flex-start; }
  .new-memo-form textarea { flex: 1; min-height: 56px; resize: vertical; }
  .memo-board {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 14px;
  }
  .memo-card {
    display: block;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
    text-decoration: none;
    color: var(--ink);
  }
  .memo-card:hover { border-color: var(--accent); }
  .memo-card .memo-preview {
    white-space: pre-wrap;
    word-break: break-word;
    min-height: 60px;
    font-size: 0.92rem;
  }
  .memo-meta {
    font-size: 0.78rem;
    color: var(--ink-muted);
    margin-top: 6px;
  }
  .memo-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 10px;
  }
  .empty-board { text-align: center; padding: 40px 0; color: var(--ink-muted); }
  .detail-card {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin-top: 16px;
  }
  .detail-card textarea {
    width: 100%;
    min-height: 240px;
    resize: vertical;
  }
</style>
</head>
<body>
<div class="nav">
  <a class="brand" href="{{ url_for('index') }}">메모장</a>
  <div class="links">
    {% if session.get('username') %}
      <span>{{ session['username'] }}</span>
      <a href="{{ url_for('logout') }}">로그아웃</a>
    {% else %}
      <a href="{{ url_for('login') }}">로그인</a>
      <a href="{{ url_for('signup') }}">회원가입</a>
    {% endif %}
  </div>
</div>
<div class="flash-wrap">
{% for message in get_flashed_messages() %}
  <div class="flash">{{ message }}</div>
{% endfor %}
</div>
<div class="page">
"""

FOOTER = """
</div>
</body>
</html>
"""

INTRO_CONTENT = """
<div class="intro">
  <h1>메모장</h1>
  <p>가입 후 로그인하면 메모를 작성하고 관리할 수 있습니다.</p>
  <p><a href="{{ url_for('signup') }}">회원가입</a></p>
</div>
"""

MEMO_BOARD_CONTENT = """
<h1>내 메모</h1>
<form class="new-memo-form" method="post" action="{{ url_for('new_memo') }}">
  <textarea name="content" placeholder="새 메모를 입력하세요" maxlength="{{ memo_max_length }}" required></textarea>
  <button type="submit">추가</button>
</form>
{% if memos %}
<div class="memo-board">
  {% for memo in memos %}
  <a class="memo-card" style="background: {{ memo_colors[loop.index0 % memo_colors|length] }};" href="{{ url_for('memo_detail', memo_id=memo.id) }}">
    <div class="memo-preview">{{ memo.preview }}</div>
    <div class="memo-meta">{{ memo.updated_at }} 수정</div>
  </a>
  {% endfor %}
</div>
{% else %}
<div class="empty-board">작성된 메모가 없습니다.</div>
{% endif %}
"""

MEMO_DETAIL_CONTENT = """
<a href="{{ url_for('index') }}">← 목록으로</a>
<div class="detail-card">
  <form method="post" action="{{ url_for('edit_memo', memo_id=memo.id) }}">
    <textarea name="content" maxlength="{{ memo_max_length }}" required>{{ memo.content }}</textarea>
    <div class="memo-meta">작성 {{ memo.created_at }} · 수정 {{ memo.updated_at }}</div>
    <div class="memo-actions">
      <button type="submit" class="secondary" formaction="{{ url_for('delete_memo', memo_id=memo.id) }}">삭제</button>
      <button type="submit">저장</button>
    </div>
  </form>
</div>
"""

SIGNUP_CONTENT = """
<h1>회원가입</h1>
<form class="auth-form" method="post">
    <label>아이디 (영문/숫자/밑줄 3~20자)</label>
    <input type="text" name="username" value="{{ username }}" maxlength="20" required>
    <label>비밀번호 (4자 이상)</label>
    <input type="password" name="password" maxlength="128" required>
    <label>비밀번호 확인</label>
    <input type="password" name="password_confirm" maxlength="128" required>
    <input type="submit" value="가입하기">
</form>
"""

LOGIN_CONTENT = """
<h1>로그인</h1>
<form class="auth-form" method="post">
    <label>아이디</label>
    <input type="text" name="username" value="{{ username }}" maxlength="20" required>
    <label>비밀번호</label>
    <input type="password" name="password" maxlength="128" required>
    <input type="submit" value="로그인">
</form>
"""


def render_page(content, **context):
    return render_template_string(HEADER + content + FOOTER, **context)


@app.route("/")
def index():
    if session.get("username"):
        db = get_db()
        rows = db.execute(
            "SELECT id, content, updated_at FROM memo WHERE user_id = ? ORDER BY updated_at DESC",
            (session["user_id"],),
        ).fetchall()
        memos = [
            {
                "id": row["id"],
                "preview": make_preview(row["content"]),
                "updated_at": format_timestamp(row["updated_at"]),
            }
            for row in rows
        ]
        return render_page(MEMO_BOARD_CONTENT, memos=memos, memo_colors=MEMO_COLORS, memo_max_length=MEMO_MAX_LENGTH)

    return render_page(INTRO_CONTENT)


@app.route("/memos/<int:memo_id>")
@login_required
def memo_detail(memo_id):
    db = get_db()
    row = db.execute(
        "SELECT id, content, created_at, updated_at FROM memo WHERE id = ? AND user_id = ?",
        (memo_id, session["user_id"]),
    ).fetchone()
    if row is None:
        flash("메모를 찾을 수 없습니다.")
        return redirect(url_for("index"))

    memo = {
        "id": row["id"],
        "content": row["content"],
        "created_at": format_timestamp(row["created_at"]),
        "updated_at": format_timestamp(row["updated_at"]),
    }
    return render_page(MEMO_DETAIL_CONTENT, memo=memo, memo_max_length=MEMO_MAX_LENGTH)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("username"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")

        if not USERNAME_PATTERN.match(username):
            flash("아이디는 영문/숫자/밑줄(_) 3~20자여야 합니다.")
            return render_page(SIGNUP_CONTENT, username=username)

        if not (PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH):
            flash(f"비밀번호는 {PASSWORD_MIN_LENGTH}자 이상, {PASSWORD_MAX_LENGTH}자 이하여야 합니다.")
            return render_page(SIGNUP_CONTENT, username=username)

        if password != password_confirm:
            flash("비밀번호가 일치하지 않습니다.")
            return render_page(SIGNUP_CONTENT, username=username)

        db = get_db()
        existing = db.execute("SELECT id FROM user WHERE username = ?", (username,)).fetchone()
        if existing is not None:
            flash("이미 존재하는 아이디입니다.")
            return render_page(SIGNUP_CONTENT, username=username)

        db.execute(
            "INSERT INTO user (username, password) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
        db.commit()
        flash("회원가입이 완료되었습니다. 로그인해주세요.")
        return redirect(url_for("login"))

    return render_page(SIGNUP_CONTENT, username="")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("username"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute("SELECT * FROM user WHERE username = ?", (username,)).fetchone()

        if user is None or not check_password_hash(user["password"], password):
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")
            return render_page(LOGIN_CONTENT, username=username)

        session.clear()
        session["username"] = user["username"]
        session["user_id"] = user["id"]
        flash(f"{user['username']}님, 로그인되었습니다.")
        return redirect(url_for("index"))

    return render_page(LOGIN_CONTENT, username="")


@app.route("/logout")
def logout():
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for("index"))


@app.route("/memos/new", methods=["POST"])
@login_required
def new_memo():
    content = request.form.get("content", "").strip()
    if not content:
        flash("메모 내용을 입력해주세요.")
    elif len(content) > MEMO_MAX_LENGTH:
        flash(f"메모는 {MEMO_MAX_LENGTH}자 이하로 작성해주세요.")
    else:
        now = datetime.utcnow().isoformat()
        db = get_db()
        db.execute(
            "INSERT INTO memo (user_id, content, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (session["user_id"], content, now, now),
        )
        db.commit()
        flash("메모를 추가했습니다.")
    return redirect(url_for("index"))


@app.route("/memos/<int:memo_id>/edit", methods=["POST"])
@login_required
def edit_memo(memo_id):
    content = request.form.get("content", "").strip()
    if not content:
        flash("메모 내용을 입력해주세요.")
        return redirect(url_for("memo_detail", memo_id=memo_id))
    if len(content) > MEMO_MAX_LENGTH:
        flash(f"메모는 {MEMO_MAX_LENGTH}자 이하로 작성해주세요.")
        return redirect(url_for("memo_detail", memo_id=memo_id))

    db = get_db()
    memo = db.execute(
        "SELECT id FROM memo WHERE id = ? AND user_id = ?", (memo_id, session["user_id"])
    ).fetchone()
    if memo is None:
        flash("메모를 찾을 수 없습니다.")
        return redirect(url_for("index"))

    db.execute(
        "UPDATE memo SET content = ?, updated_at = ? WHERE id = ?",
        (content, datetime.utcnow().isoformat(), memo_id),
    )
    db.commit()
    flash("메모를 수정했습니다.")
    return redirect(url_for("memo_detail", memo_id=memo_id))


@app.route("/memos/<int:memo_id>/delete", methods=["POST"])
@login_required
def delete_memo(memo_id):
    db = get_db()
    cursor = db.execute("DELETE FROM memo WHERE id = ? AND user_id = ?", (memo_id, session["user_id"]))
    db.commit()
    if cursor.rowcount == 0:
        flash("메모를 찾을 수 없습니다.")
    else:
        flash("메모를 삭제했습니다.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    debug = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
    port = int(os.environ.get("FLASK_PORT", "5000"))
    app.run(debug=debug, port=port)
