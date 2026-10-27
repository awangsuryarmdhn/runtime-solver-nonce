"""Retry loop for the NONCE Genesis free mint (TURBO mode).

Runs driver.py once per attempt and decides from its FINAL_REPORT_JSON:
- MINTED -> stop, success.
- STOPPED at protocol_info (admission closed) -> stop, report.
- EXPIRED_NO_SUBMIT / NOT_WIN -> fresh attempt (driver generates a new
  UUID each run), repeat until one mint succeeds.
- STOPPED with pending-attempt evidence -> wait 960s (pending attempt
  deadline expiry) then retry.
- STOPPED with hard evidence (sold out, no quota, identity/devMode/
  verification failure) -> stop, report.
- Other STOPPED / crash without report -> transient; retry after 30s,
  but stop after 5 consecutive transient failures to avoid an unbounded
  loop when nobody is tapping approvals.

No secrets are handled here; the driver holds tokens in memory only.
"""
import json
import os
import subprocess
import sys
import time

HERE = "/home/hatch/workspace/nonce-mint"
DRIVER = os.path.join(HERE, "venv", "bin", "python")
SCRIPT = os.path.join(HERE, "driver.py")
LOGDIR = os.path.join(HERE, "runs")

HARD_MARKERS = ("sold out", "no remaining", "mintedbywallet", "devmode",
                "verification failed", "agent id", "quota", "identity",
                "handle", "not claimed", "address mismatch")


def run_once(n):
    os.makedirs(LOGDIR, exist_ok=True)
    ts = time.strftime("%Y-%m-%d-%H%M%S")
    logpath = os.path.join(LOGDIR, f"attempt-{n}-{ts}.log")
    with open(logpath, "w") as lf:
        p = subprocess.Popen([DRIVER, SCRIPT], stdout=lf, stderr=subprocess.STDOUT)
        p.wait()
    with open(logpath) as lf:
        out = lf.read()
    report = None
    if "===== FINAL_REPORT_JSON =====" in out:
        try:
            report = json.loads(out.rsplit("===== FINAL_REPORT_JSON =====", 1)[1].strip())
        except Exception:
            report = None
    return p.returncode, report, logpath


def main():
    n = 0
    transient_streak = 0
    while True:
        n += 1
        print(f"LOOP attempt {n} starting", flush=True)
        rc, report, logpath = run_once(n)
        if report is None:
            transient_streak += 1
            print(f"LOOP attempt {n}: driver exited rc={rc} WITHOUT report (log {logpath})", flush=True)
            if transient_streak >= 5:
                print("LOOP_DECISION: STOP transient_crash_streak", flush=True)
                return 1
            time.sleep(30)
            continue
        outcome = report.get("outcome")
        step = report.get("stoppedStep")
        evidence = str(report.get("evidence") or "")
        print(f"LOOP attempt {n}: outcome={outcome} stoppedStep={step} "
              f"attemptId={report.get('attemptId')} fragments={report.get('fragmentsCollected')} "
              f"solve={report.get('solveResult')} log={logpath}", flush=True)
        if outcome == "MINTED":
            print(f"LOOP_DECISION: MINTED {json.dumps(report.get('mint'))} log={logpath}", flush=True)
            return 0
        if outcome == "STOPPED" and step == "protocol_info":
            print(f"LOOP_DECISION: STOP admission_closed evidence={evidence} log={logpath}", flush=True)
            return 0
        if outcome in ("EXPIRED_NO_SUBMIT", "NOT_WIN"):
            transient_streak = 0
            print("LOOP attempt failed with no fee; retrying with a fresh attempt in 10s", flush=True)
            time.sleep(10)
            continue
        # Other STOPPED: classify.
        ev = evidence.lower()
        if "pending" in ev:
            print("LOOP pending attempt detected; waiting 960s for its deadline to expire", flush=True)
            time.sleep(960)
            continue
        if any(m in ev for m in HARD_MARKERS):
            print(f"LOOP_DECISION: STOP hard_failure evidence={evidence} log={logpath}", flush=True)
            return 1
        transient_streak += 1
        print(f"LOOP transient stop (streak {transient_streak}); retry in 30s", flush=True)
        if transient_streak >= 5:
            print(f"LOOP_DECISION: STOP transient_streak evidence={evidence} log={logpath}", flush=True)
            return 1
        time.sleep(30)


if __name__ == "__main__":
    sys.exit(main())
