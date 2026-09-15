import os
import subprocess
import sys
import time

WATCHED_FILES = ["app.py", ".env"]
CHECK_INTERVAL = 1.0


def snapshot():
    return {f: os.path.getmtime(f) for f in WATCHED_FILES if os.path.exists(f)}


def start():
    return subprocess.Popen([sys.executable, "app.py"])


def main():
    proc = start()
    last = snapshot()
    print("[watch] app.py / .env 변경 감지 중... (Ctrl+C로 종료)", flush=True)
    try:
        while True:
            time.sleep(CHECK_INTERVAL)
            current = snapshot()
            if current != last:
                last = current
                print("[watch] 변경 감지, 서버 재시작", flush=True)
                proc.terminate()
                proc.wait()
                proc = start()
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        proc.wait()


if __name__ == "__main__":
    main()
