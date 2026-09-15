import os
import re
import sqlite3

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
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "memo.db")

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")
PASSWORD_MIN_LENGTH = 4
PASSWORD_MAX_LENGTH = 128

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
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
        db.commit()


BASE_TEMPLATE = """
<!doctype html>
<html>
<head><title>메모 서비스</title></head>
<body>
{% if session.get('username') %}
    <p>{{ session['username'] }}님 환영합니다.</p>
    <p><a href="{{ url_for('logout') }}">로그아웃</a></p>
{% else %}
    <p><a href="{{ url_for('login') }}">로그인</a> | <a href="{{ url_for('signup') }}">회원가입</a></p>
{% endif %}
<hr>
{% for message in get_flashed_messages() %}
    <p>{{ message }}</p>
{% endfor %}
{{ body|safe }}
</body>
</html>
"""

INDEX_BODY = "<h1>메모 서비스</h1>"

SIGNUP_BODY = """
<h1>회원가입</h1>
<form method="post">
    아이디 (영문/숫자/밑줄 3~20자): <input type="text" name="username" value="{username}" maxlength="20" required><br>
    비밀번호 (4자 이상): <input type="password" name="password" maxlength="128" required><br>
    비밀번호 확인: <input type="password" name="password_confirm" maxlength="128" required><br>
    <input type="submit" value="가입하기">
</form>
"""

LOGIN_BODY = """
<h1>로그인</h1>
<form method="post">
    아이디: <input type="text" name="username" value="{username}" maxlength="20" required><br>
    비밀번호: <input type="password" name="password" maxlength="128" required><br>
    <input type="submit" value="로그인">
</form>
"""


def render(body):
    return render_template_string(BASE_TEMPLATE, body=body)


@app.route("/")
def index():
    return render(INDEX_BODY)


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
            return render(SIGNUP_BODY.format(username=escape(username)))

        if not (PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH):
            flash(f"비밀번호는 {PASSWORD_MIN_LENGTH}자 이상, {PASSWORD_MAX_LENGTH}자 이하여야 합니다.")
            return render(SIGNUP_BODY.format(username=escape(username)))

        if password != password_confirm:
            flash("비밀번호가 일치하지 않습니다.")
            return render(SIGNUP_BODY.format(username=escape(username)))

        db = get_db()
        existing = db.execute(
            "SELECT id FROM user WHERE username = ?", (username,)
        ).fetchone()
        if existing is not None:
            flash("이미 존재하는 아이디입니다.")
            return render(SIGNUP_BODY.format(username=escape(username)))

        db.execute(
            "INSERT INTO user (username, password) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
        db.commit()
        flash("회원가입이 완료되었습니다. 로그인해주세요.")
        return redirect(url_for("login"))

    return render(SIGNUP_BODY.format(username=""))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("username"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()

        if user is None or not check_password_hash(user["password"], password):
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")
            return render(LOGIN_BODY.format(username=escape(username)))

        session.clear()
        session["username"] = user["username"]
        flash(f"{user['username']}님, 환영합니다!")
        return redirect(url_for("index"))

    return render(LOGIN_BODY.format(username=""))


@app.route("/logout")
def logout():
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    debug = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
    port = int(os.environ.get("FLASK_PORT", "5000"))
    app.run(debug=debug, port=port)
