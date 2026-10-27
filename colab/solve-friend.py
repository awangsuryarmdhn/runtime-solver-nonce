#!/usr/bin/env python3
# NONCE Genesis portfolio SAT solver. Usage: python3 solve.py soal.cnf > jawaban.txt
# Needs: pip install python-sat
import sys, json, multiprocessing as mp
from pysat.solvers import Solver

SOLVERS = ["cadical195", "cadical153", "glucose4", "maplechrono", "lingeling", "minisat22", "glucose3", "maplesat"]

def load(path):
    txt = open(path).read().strip()
    if txt.startswith("["):
        cls = json.loads(txt)
        n = max(abs(l) for c in cls for l in c)
        return n, cls
    n, cls, cur = 0, [], []
    for line in txt.splitlines():
        line = line.strip()
        if not line or line[0] == "c":
            continue
        if line[0] == "p":
            n = int(line.split()[2]); continue
        for t in line.split():
            v = int(t)
            if v == 0:
                if cur: cls.append(cur); cur = []
            else:
                cur.append(v)
    if cur: cls.append(cur)
    return n, cls

def run(name, n, cls, q):
    try:
        with Solver(name=name, bootstrap_with=cls) as s:
            if s.solve():
                q.put((name, s.get_model()))
    except Exception as e:
        print(f"{name} error: {e}", file=sys.stderr)

if __name__ == "__main__":
    n, cls = load(sys.argv[1])
    cores = mp.cpu_count()
    names = SOLVERS[:max(2, min(len(SOLVERS), cores))]
    print(f"{n} vars, {len(cls)} clauses, running {names}", file=sys.stderr)
    q = mp.Queue()
    ps = [mp.Process(target=run, args=(nm, n, cls, q)) for nm in names]
    for p in ps: p.start()
    name, model = q.get()
    for p in ps: p.terminate()
    val = {abs(l): l > 0 for l in model}
    assert all(any(val.get(abs(l), False) == (l > 0) for l in c) for c in cls), "verify failed"
    print(f"solved by {name}, verified all clauses", file=sys.stderr)
    print("".join("1" if val.get(i, False) else "0" for i in range(1, n + 1)))
