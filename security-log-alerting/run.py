"""Start backend (port 8000) and dashboard (port 8501) together: python run.py"""
import subprocess
import sys
import time

procs = [subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", "8000"]),
         subprocess.Popen([sys.executable, "-m", "streamlit", "run", "dashboard.py",
                           "--server.port", "8501"])]
try:
    while all(p.poll() is None for p in procs):
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    for p in procs:
        p.terminate()
