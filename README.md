## 메모 서비스 (회원가입/로그인)

Flask + SQLite로 만든 간단한 메모 서비스입니다. 현재는 회원가입, 로그인, 로그아웃 기능만 구현되어 있습니다.

### 설치

```bash
pip install -r requirements.txt
```

### 환경변수

`.env.example`을 복사해 `.env`를 만들고 필요하면 값을 수정하세요.

```bash
cp .env.example .env
```

- `SECRET_KEY` — Flask 세션 서명에 사용되는 키
- `FLASK_DEBUG` — 디버그 모드 여부
- `FLASK_PORT` — 실행 포트
- `SESSION_COOKIE_SECURE` — HTTPS 환경에서만 세션 쿠키 전송

`.env`와 그 변형(`.env.local` 등)은 `.gitignore`에 포함되어 있어 커밋되지 않습니다. `.env.example`만 커밋됩니다.

### 실행

```bash
python app.py
```

실행하면 프로젝트 폴더에 `memo.db` (SQLite) 파일이 자동으로 생성됩니다.

브라우저에서 http://127.0.0.1:5000 으로 접속하세요.

### 기능

- 회원가입 (`/signup`)
  - 아이디: 영문/숫자/밑줄(`_`) 3~20자
  - 비밀번호: 4~128자, 비밀번호 확인 입력 필요
  - 중복 아이디 가입 방지
- 로그인 (`/login`) — 로그인 성공 시 세션 유지, 이미 로그인된 상태면 자동으로 메인으로 이동
- 로그아웃 (`/logout`)
- 각 동작 결과를 화면 상단 메시지로 안내 (가입 완료, 로그인 실패 등)

### 보안

- 비밀번호는 평문 저장 없이 `werkzeug.security`로 해시하여 저장
- 모든 SQL 쿼리는 파라미터 바인딩(`?`)을 사용해 SQL 인젝션을 방지
- 세션 쿠키는 `HttpOnly`, `SameSite=Lax`로 설정 (운영 환경에서는 `SESSION_COOKIE_SECURE=true`로 HTTPS 강제 권장)
- `.gitignore`에서 `.env*`, DB 파일(`*.db`, `*.sqlite3`), 로그, IDE/OS 설정 파일 등을 폭넓게 제외해 민감 정보 실수 업로드를 방지

### 파일 구성

- `app.py` — Flask 앱 전체 (라우트, DB 초기화 포함)
- `requirements.txt` — 의존성 목록
- `.env` — 로컬 환경변수 (git에 커밋되지 않음)
- `.env.example` — 환경변수 예시 템플릿
- `memo.db` — 최초 실행 시 자동 생성되는 SQLite DB 파일
