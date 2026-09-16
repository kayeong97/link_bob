# Penguin Memo

Flask와 SQLite로 만든 개인 메모 서비스입니다. 회원가입과 로그인, 사용자별 메모 CRUD, 관리자 전용 회원 조회 기능을 제공합니다.

## 주요 기능

- 회원가입 및 로그인
- 사용자별 메모 작성, 조회, 수정, 삭제
- 메모 소유권 검증을 통한 다른 사용자 메모 접근 차단
- 초기 관리자 계정과 관리자 전용 메모 자동 생성
- 관리자 전용 전체 회원 목록 조회 (`/admin/users`)

## 설치

Python 3.10 이상을 권장합니다.

```bash
python -m venv .venv
```

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

macOS / Linux:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## 환경변수

`.env.example`을 `.env`로 복사한 뒤 모든 플레이스홀더를 실제 값으로 교체합니다.

```bash
cp .env.example .env
```

필수 설정:

- `SECRET_KEY`: 32자 이상의 예측 불가능한 세션 서명 키
- `ADMIN_PASSWORD`: 12~128자의 관리자 초기 비밀번호
- `ADMIN_MEMO_CONTENT`: `SBOB{...}` 형식의 관리자 초기 메모

서버 설정:

- `FLASK_PORT`: 서버 포트
- `BIND_HOST`: 서버가 바인딩할 주소
- `TRUSTED_HOSTS`: 허용할 호스트 목록
- `SESSION_COOKIE_SECURE`: HTTPS에서 `true`로 설정

실제 비밀번호, 플래그, 세션 키가 들어 있는 `.env`는 절대 커밋하지 마세요. `.env`, SQLite DB, 로그 파일은 `.gitignore`에서 제외됩니다.

## 실행

```bash
python app.py
```

앱 시작 시 DB 스키마가 생성 또는 마이그레이션됩니다. 관리자 계정과 초기 메모는 존재하지 않을 때 한 번만 생성됩니다.

waitress로 띄우기 때문에 코드를 수정해도 자동으로 재시작되지 않습니다. 개발 중에는 아래처럼 파일 변경을 감지해 자동으로 서버를 재시작하는 스크립트를 대신 사용하세요.

```bash
python watch_run.py
```

`app.py` 또는 `.env`가 바뀔 때마다 기존 서버를 종료하고 새로 띄웁니다.

## Notes API 보안 사용법

API는 웹 로그인으로 만들어진 세션 쿠키를 사용합니다. 상태를 변경하는 요청에는 먼저
`GET /api/csrf-token`으로 토큰을 발급받고 같은 세션 쿠키와 함께
`X-CSRF-Token` 헤더로 보내야 합니다.

```text
GET  /api/csrf-token
GET  /api/notes
POST /api/notes              X-CSRF-Token: <발급받은 토큰>
GET  /api/notes/<note_id>
```

## 적용된 보안 설정

- 비밀번호 단방향 해시 저장
- 모든 SQL 쿼리 파라미터 바인딩
- 서버 측 DB 역할을 이용한 관리자 권한 검증
- 메모 조회·수정·삭제 시 사용자 소유권 검증
- 모든 상태 변경 요청에 CSRF 토큰 검증
- Jinja 자동 이스케이프를 통한 저장형 XSS 방어
- 로그인 실패 횟수 제한
- 세션 쿠키 `HttpOnly`, `SameSite=Lax` 적용
- CSP, 클릭재킹 방지, MIME 스니핑 방지 등 보안 헤더 적용
- 요청 본문 크기 제한 및 신뢰할 호스트 검증
- Flask 개발 서버 대신 Waitress 사용

## 파일 구성

- `app.py`: 애플리케이션, 라우트, DB 초기화
- `watch_run.py`: 개발용 자동 재시작 스크립트 (`app.py`/`.env` 변경 감지)
- `requirements.txt`: Python 의존성
- `.env.example`: 공개 가능한 환경변수 템플릿
