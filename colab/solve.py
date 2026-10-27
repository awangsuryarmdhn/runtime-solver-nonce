#!/usr/bin/env python3
"""NONCE Genesis portfolio 5-SAT solver (standalone, for a many-core machine).

Usage:
    pip install python-sat
    python3 solve.py soal.cnf > jawaban.txt

Input : DIMACS CNF file (soal.cnf, one problem per attempt, unique per agent)
        or a JSON list of clauses, e.g. [[1, -2, 3, -4, 5], ...].
Output: jawaban.txt contains ONLY the verified assignment bitstring
        (exactly n_vars chars of 0/1, char k-1 = variable k).
        All diagnostics go to stderr, never to stdout.
Exit  : 0 = verified SAT bitstring printed; 1 = UNSAT, timeout, or error
        (nothing on stdout, so an empty jawaban.txt is never submitted).

Race rule: every solver runs in its own process (one per core), the
first assignment verified against EVERY clause wins, the rest are killed.
Never submit a bitstring that has not passed verify_assignment here.

Security: this script only ever sees clause data (puzzle data). It needs
no token, capability, signature, wallet, or network access of any kind.
"""
import json
import multiprocessing as mp
import os
import sys
import time

from pysat.solvers import Solver

# Portfolio order follows the example the user shared; as many solvers as
# cores are used (minimum 2), so a many-core machine really races.
SOLVERS = ['cadical195', 'cadical153', 'glucose4', 'maplechrono',
           'lingeling', 'minisat22', 'glucose3', 'maplesat']


def eprint(*args):
    print(*args, file=sys.stderr, flush=True)


def load(path):
    txt = open(path).read().strip()
    if txt.startswith('['):
        cls = json.loads(txt)
        n = max(abs(l) for c in cls for l in c)
        return n, cls
    n, cls, cur = 0, [], []
    for line in txt.splitlines():
        line = line.strip()
        if not line or line[0] == 'c':
            continue
        if line[0] == 'p':
            n = int(line.split()[2])
            continue
        for t in line.split():
            v = int(t)
            if v == 0:
                if cur:
                    cls.append(cur)
                    cur = []
            else:
                cur.append(v)
    if cur:
        cls.append(cur)
    return n, cls


def verify_assignment(clauses, assignment):
    if isinstance(assignment, str):
        a = {i + 1: (ch == '1') for i, ch in enumerate(assignment)}
    else:
        a = {abs(l): (l > 0) for l in assignment}
    for clause in clauses:
        ok = False
        for lit in clause:
            if a.get(abs(lit), False) == (lit > 0):
                ok = True
                break
        if not ok:
            return False
    return True


def to_bitstring(model, n_vars):
    a = {abs(l): (l > 0) for l in model}
    return ''.join('1' if a.get(i, False) else '0'
                   for i in range(1, n_vars + 1))


def _worker(name, clauses, queue):
    try:
        with Solver(name=name, bootstrap_with=clauses) as s:
            if s.solve():
                queue.put((name, True, s.get_model()))
            else:
                queue.put((name, False, None))
    except Exception as e:
        queue.put((name, False, 'error: %s' % e))


def portfolio_solve(clauses, n_vars, time_limit):
    cores = max(1, os.cpu_count() or 1)
    names = SOLVERS[:max(2, min(len(SOLVERS), cores))]
    eprint('cores: %d -> solvers: %s' % (cores, ', '.join(names)))
    try:
        ctx = mp.get_context('fork')
    except Exception:
        ctx = mp.get_context()
    queue = ctx.Queue()
    procs = []
    for name in names:
        p = ctx.Process(target=_worker, args=(name, clauses, queue))
        p.start()
        procs.append(p)
    deadline = time.time() + time_limit
    result, winner = None, None
    finished = 0
    while time.time() < deadline and finished < len(procs):
        try:
            name, sat, model = queue.get(timeout=5)
            finished += 1
            if sat and model is not None:
                bits = to_bitstring(model, n_vars)
                if verify_assignment(clauses, bits):
                    result, winner = bits, name
                    eprint('winner: %s (verified against all clauses)' % name)
                    break
                eprint('rejected unverified model from %s' % name)
        except Exception:
            pass
    for p in procs:
        if p.is_alive():
            p.terminate()
    for p in procs:
        p.join(timeout=5)
    if result is not None:
        return result, winner
    return None, ('timeout' if time.time() >= deadline else 'unsat_or_error')


def main(argv):
    if len(argv) < 2:
        eprint('usage: python3 solve.py soal.cnf [time_limit_seconds] > jawaban.txt')
        return 1
    time_limit = int(argv[2]) if len(argv) > 2 else 780
    n_vars, clauses = load(argv[1])
    eprint('loaded: %d vars, %d clauses' % (n_vars, len(clauses)))
    bits, status = portfolio_solve(clauses, n_vars, time_limit)
    if bits:
        sys.stdout.write(bits + '\n')
        sys.stdout.flush()
        return 0
    eprint('no verified solution (%s)' % status)
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
