# runtime-solver-nonce

Arsip teknik solver + attempt runner NONCE Genesis (free mint, BNB Chain).
File yang dibutuhin tinggal tarik dari repo ini.

## Isi

- `colab/solve.py` — solver portfolio 5-SAT standalone (rekomendasi buat live run).
- `colab/solve-friend.py` — versi asli yang dibagikan teman (referensi saja;
  ada 2 kelemahan: gantung kalau UNSAT, dan crash kalau model pertama gagal
  verifikasi tanpa fallback ke solver lain).
- `colab/turbo-solver-5sat.ipynb` — versi notebook Colab dari portfolio yang
  sama (8 solver, mode upload + mode siaga).
- `driver.py` — attempt runner lengkap: MCP auth, prepare/start attempt,
  kumpul fragment, solve, verifikasi, submit, mint. Butuh Binance Agentic
  Wallet (`baw`) di mesin agent; bukan buat jalan mentah di Colab.
- `mcp_client.py` — klien MCP NONCE (retry 429 + Retry-After, dll).
- `run_loop.py` — pelari driver.

## Tarik & pakai solver (mesin mana pun / Colab)

```bash
git clone https://github.com/awangsuryarmdhn/runtime-solver-nonce
pip install python-sat
python3 runtime-solver-nonce/colab/solve.py soal.cnf > jawaban.txt
```

- Input: DIMACS `.cnf` atau JSON list klausa.
- Output: `jawaban.txt` hanya berisi bitstring `0/1` sepanjang jumlah
  variabel (karakter ke-k-1 = variabel k). Semua diagnostik ke stderr,
  tidak ke stdout.
- Portfolio: 8 solver (cadical195, cadical153, glucose4, maplechrono,
  lingeling, minisat22, glucose3, maplesat), dipakai sebanyak core
  (minimal 2), adu cepat — yang menang yang pertama TERVERIFIKASI ke
  semua klausa.
- Batas default 780 detik. Kalau tidak ada solusi terverifikasi
  (UNSAT/timeout), exit 1 dan `jawaban.txt` kosong — jangan submit.

## Skema race (penting)

- Soal (`soal.cnf`) unik per attempt per agent, tidak bisa dipakai ulang.
- Begitu attempt aktif: soal.cnf keluar → solver jalan di mesin core
  banyak → jawaban.txt balik → verifikasi lokal ke SEMUA klausa → baru
  submit. Bitstring yang belum terverifikasi tidak pernah di-submit.
- Kalau semua solver UNSAT: biarkan attempt expired (tidak ada fee),
  jangan submit jawaban mentah.
- Deadline attempt 900 detik dari `start_attempt`; sisakan ~120 detik
  untuk submit + mint.

## Keamanan

- Yang masuk ke mesin solver hanya klausa (data puzzle). Tidak pernah
  token, capability, signature, private key, atau seed.
- Bearer MCP & capability hanya di memori proses driver, tidak pernah
  ditulis ke file, log, atau repo ini.
- Driver menandatangani EIP-712 hanya untuk auth MCP + StartAuthorization
  + MintAuthorization yang sudah diverifikasi; tidak pernah Permit /
  personal_sign, tidak pernah approve token / pembayaran / swap.

## Profil soal

`nonce-logic-balanced-1536`: 1.536 variabel, 33.792 klausa,
5 literal/klausa, 32 fragment, budget 96 tool, deadline 900 detik.
