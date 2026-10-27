"""NONCE Genesis single-attempt driver.

Runs the full MCP challenge flow for exactly ONE free mint attempt, then
stops and reports. Secrets policy (hard):
- The MCP Bearer token and any capability are held in memory only.
- NEVER print/log/write the token, a capability, or any signature.
- Logs contain only phase markers, public addresses, counts, and
  non-sensitive status fields (attempt UUID, benchmark, tokenId, txHash).
- Long hex/JSON args are passed to baw via subprocess argv lists only.

Usage: venv/bin/python driver.py
"""
import json
import os
import random
import subprocess
import sys
import time
import uuid

sys.path.insert(0, "/home/hatch/workspace/nonce-mint")
from mcp_client import MCPClient, RateLimited, ToolError, retry_with_backoff  # noqa: E402

import requests  # noqa: E402
from Crypto.Hash import keccak  # noqa: E402

BAW = "/home/hatch/.npm-global/bin/baw"
WALLET = "0xd9295f409b7875c0076Bd9B8Db070Ad8EE8fc2d6"
FREEMINT = "0x7538ba8C1A82E9706dB6d2463C15f69ADc01a17e"
NFT = "0x053259A3D30E63d9447E3d90813C6a494bcB398a"
AGENTGATE = "0xc8D8EebAd7Fdd590edA6d23164B1eC014913Ce8f"
REGISTRY = "0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F"
CHAIN = 56
MCP_URL = "https://mcp.nonceprotocol.xyz/mcp"
AUTH_CHALLENGE = "https://mcp.nonceprotocol.xyz/auth/challenge"
AUTH_VERIFY = "https://mcp.nonceprotocol.xyz/auth/verify"
EXPECTED_HANDLE = "leviathan"

RPC_URLS = [
    "https://bsc-dataseed.bnbchain.org",
    "https://bsc-dataseed1.defibit.io",
    "https://bsc-dataseed2.defibit.io",
    "https://bsc-dataseed3.defibit.io",
    "https://bsc-dataseed4.defibit.io",
    "https://bsc-dataseed1.ninicoin.io",
    "https://bsc.publicnode.com",
    "https://bsc-dataseed.binance.org",
]

T0 = time.time()

from datetime import timezone as _tz, timedelta as _td, datetime as _dt
WIB = _tz(_td(hours=7))


def wib_now():
    return _dt.now(WIB).strftime("%Y-%m-%dT%H:%M:%S+07:00")


def log(phase, msg):
    print(f"[{time.time() - T0:8.1f}s] {phase}: {msg}", flush=True)


def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def sel(signature: str) -> str:
    return "0x" + keccak256(signature.encode()).hex()[:8]


def addr_pad(addr: str) -> str:
    return "0" * 24 + addr.lower().replace("0x", "")


def dec_uint(hexdata: str) -> int:
    return int(hexdata, 16) if hexdata else 0


def dec_bool(hexdata: str) -> bool:
    h = hexdata.replace("0x", "")
    return h[-2:] != "00" if h else False


def dec_address(hexdata: str) -> str:
    h = hexdata.replace("0x", "")
    return "0x" + h[-40:]


def dec_bytes32(hexdata: str) -> str:
    h = hexdata.replace("0x", "")
    return "0x" + h[-64:].rjust(64, "0")


# ---------------------------------------------------------------- baw
def run_baw(args, timeout=180):
    """Run baw via argv. Returns parsed JSON dict (or error dict)."""
    proc = subprocess.run(
        [BAW] + args, capture_output=True, text=True, timeout=timeout
    )
    out = proc.stdout.strip()
    try:
        return json.loads(out) if out else {"success": False, "error": {"message": "empty baw output", "stderr": proc.stderr[:300]}}
    except json.JSONDecodeError:
        return {"success": False, "error": {"message": "non-JSON baw output", "stdout": out[:300], "stderr": proc.stderr[:300]}}


def baw_ok(data):
    return isinstance(data, dict) and data.get("success") is True


def sign_eip712_via_baw(wallet_request_str, label):
    """Preview + execute an EIP-712 sign request. Returns (signature, recovery).
    Polls sign-message result while PENDING_CONFIRMATION (user taps in app).
    Never logs the signature."""
    prev = run_baw(
        ["sign-message", "preview", "--binanceChainId", "56",
         "--signType", "EIP712", "--message", wallet_request_str, "--json"],
        timeout=180,
    )
    if not baw_ok(prev):
        raise RuntimeError(f"{label} sign preview failed: {json.dumps(prev)[:600]}")
    data = prev["data"]
    req_id = data.get("requestId")
    pm = data.get("parsedMessage", {})
    log(label, f"sign preview ok requireConfirmation={data.get('requireConfirmation')} parsedType={pm.get('messageType')}")
    risks = (data.get("risks") or {}).get("riskDetails") or []
    if risks:
        log(label, "sign preview risks: " + "; ".join(f"{r.get('title')}" for r in risks))
    if not req_id:
        raise RuntimeError(f"{label} sign preview returned no requestId")
    exe = run_baw(["sign-message", "execute", "--requestId", req_id, "--json"], timeout=180)
    if not baw_ok(exe):
        raise RuntimeError(f"{label} sign execute failed: {json.dumps(exe)[:600]}")
    ed = exe["data"]
    status = ed.get("status")
    if status == "COMPLETED":
        log(label, "sign execute COMPLETED")
        return ed.get("signature"), ed.get("signatureRecovery")
    if status == "PENDING_CONFIRMATION":
        order_id = ed.get("orderId")
        log(label, f"sign PENDING_CONFIRMATION, polling result (order pending, user taps in app)")
        for _ in range(40):
            time.sleep(15)
            res = run_baw(["sign-message", "result", "--order-id", order_id, "--json"], timeout=120)
            if baw_ok(res):
                st = res["data"].get("status")
                if st == "COMPLETED":
                    log(label, "sign result COMPLETED")
                    return res["data"].get("signature"), res["data"].get("signatureRecovery")
                if st in ("REJECTED", "EXPIRED"):
                    raise RuntimeError(f"{label} sign result {st}")
                log(label, f"sign result still {st}, waiting")
            else:
                log(label, f"sign result poll error, retrying: {json.dumps(res)[:200]}")
        raise RuntimeError(f"{label} sign result timed out after 10 min")
    raise RuntimeError(f"{label} unexpected sign execute status: {status}")


# ---------------------------------------------------------------- RPC
def rpc_call(url, method, params, timeout=12):
    resp = requests.post(
        url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=timeout,
    )
    resp.raise_for_status()
    obj = resp.json()
    if "error" in obj:
        raise RuntimeError(f"RPC {method} error: {obj['error']}")
    return obj["result"]


def rpc_first(method, params, timeout=12):
    last = None
    for url in RPC_URLS:
        try:
            return rpc_call(url, method, params, timeout=timeout)
        except Exception as e:
            last = e
    raise RuntimeError(f"all BSC RPC endpoints failed for {method}: {last}")


def eth_call(to, data):
    return rpc_first("eth_call", [{"to": to, "data": data}, "latest"])


def eth_block_number():
    return int(rpc_first("eth_blockNumber", []), 16)


def eth_receipt(tx_hash):
    return rpc_first("eth_getTransactionReceipt", [tx_hash])

# ---------------------------------------------------------------- auth HTTP
def post_json_with_backoff(url, payload, attempts=20, label="auth"):
    last = None
    wait = 5.0
    for i in range(attempts):
        try:
            resp = requests.post(url, json=payload, timeout=30)
            if resp.status_code == 429:
                ra = resp.headers.get("Retry-After")
                try:
                    w = float(ra) if ra is not None else wait
                except ValueError:
                    w = wait
                log(label, f"HTTP 429, waiting {w:.0f}s + jitter before retry {i+1}")
                time.sleep(min(w, 60) + random.uniform(0, 3))
                wait = min(wait * 2, 60)
                continue
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            last = e
            log(label, f"request error ({type(e).__name__}), retry {i+1} in {wait:.0f}s")
            time.sleep(wait + random.uniform(0, 2))
            wait = min(wait * 2, 60)
    raise RuntimeError(f"{label} failed after {attempts} attempts: {last}")


def parse_expires_at(value):
    """Return epoch seconds for an expiresAt value, or None if unknown."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        if v > 1e12:
            return v / 1000.0
        if v > 1e9:
            return v
        return None
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            pass
        try:
            from datetime import datetime, timezone
            s = value.replace("Z", "+00:00")
            return datetime.fromisoformat(s).timestamp()
        except ValueError:
            return None
    return None


def authenticate_mcp(client, wallet):
    """Full MCP auth flow. Returns True. Token is stored only on client."""
    chal = post_json_with_backoff(AUTH_CHALLENGE, {"wallet": wallet}, label="auth-challenge")
    log("auth", f"challenge response keys: {sorted(chal.keys())}")
    challenge = chal.get("challenge")
    wallet_request = chal.get("walletRequest") or chal.get("wallet_request")
    typed = chal.get("typedData") or chal.get("typed_data")
    expires_at = chal.get("expiresAt") or chal.get("expires_at")
    if wallet_request is None and typed is None:
        raise RuntimeError(f"challenge response has neither walletRequest nor typedData: keys={sorted(chal.keys())}")
    if isinstance(wallet_request, str):
        wr_obj = json.loads(wallet_request)
        params = wr_obj.get("params", [])
        if len(params) != 2:
            raise RuntimeError("walletRequest params are not [wallet, typedData]")
        typed = json.loads(params[1]) if isinstance(params[1], str) else params[1]
        req_wallet = params[0]
    else:
        # walletRequest given as object: rebuild the exact RPC string.
        if isinstance(wallet_request, dict) and "params" in wallet_request:
            params = wallet_request["params"]
            typed = json.loads(params[1]) if isinstance(params[1], str) else params[1]
            req_wallet = params[0]
            wallet_request = json.dumps(wallet_request)
        else:
            if typed is None:
                raise RuntimeError("cannot reconstruct walletRequest from challenge response")
            req_wallet = wallet
            wallet_request = json.dumps({
                "method": "eth_signTypedData_v4",
                "params": [wallet, json.dumps(typed)],
            })
    # ---- verify typedData exactly (checks only; never log the payload)
    domain = typed.get("domain", {}) or {}
    msg = typed.get("message", {}) or {}
    checks = {
        "domain_name": domain.get("name") == "NONCE MCP Sign In",
        "domain_version": str(domain.get("version")) == "1",
        "domain_chain": int(domain.get("chainId", 0)) == 56,
        "primaryType": typed.get("primaryType") == "SignIn",
        "req_wallet": str(req_wallet).lower() == wallet.lower(),
        "msg_wallet": str(msg.get("wallet", "")).lower() == wallet.lower(),
        "audience": msg.get("audience") == "mcp.nonceprotocol.xyz",
        "challenge_match": (msg.get("challenge") == challenge) if challenge else False,
    }
    exp = parse_expires_at(msg.get("expiresAt") or msg.get("expires_at") or expires_at)
    checks["expiry_future"] = exp is not None and exp > time.time() + 60
    stmt = str(msg.get("statement", "") or msg.get("message", "") or "")
    # Negation-aware grant check: a bad word only counts when it is NOT
    # negated just before it (e.g. "does not approve ... any payment" is a
    # sign-in-only disclaimer, not a grant). Plus a structural check: the
    # SignIn type fields and message fields must be identity-only.
    # Whole-statement negation rule: the server's disclaimer negates the
    # entire clause ("does not approve tokens or authorize any payment"), so
    # a bad word only counts as a grant when the statement contains NO
    # negation at all. The structural check below is the real backstop: the
    # EIP-712 types/message contain identity fields only, so the signature
    # cannot authorize a payment or permit regardless of prose.
    low = stmt.lower()
    bad_words = ("permit", "approve", "transfer", "payment", "spend", "allowance", "swap")
    negations = ("not", "no", "never", "does not", "do not", "without", "doesn't", "don't")
    granting = any(w in low for w in bad_words) and not any(n in low for n in negations)
    log("auth", f"statement text: {stmt[:200]}")
    type_fields = set()
    for fields in (typed.get("types", {}) or {}).values():
        for f in fields or []:
            if isinstance(f, dict) and f.get("name"):
                type_fields.add(f["name"])
    grant_fields = {"spender", "value", "amount", "token", "deadline", "permit", "allowance", "to", "recipient"}
    structural_ok = not (type_fields & grant_fields) and not (set(msg.keys()) & grant_fields)
    checks["sign_in_only"] = bool(stmt) and not granting and structural_ok
    log("auth", f"statement check: granting={granting} structural_ok={structural_ok} type_fields={sorted(type_fields)}")
    log("auth", "typedData checks: " + ", ".join(f"{k}={'OK' if v else 'FAIL'}" for k, v in checks.items()))
    failed = [k for k, v in checks.items() if not v]
    if failed:
        raise RuntimeError(f"typedData verification FAILED on: {failed}; refusing to sign")
    signature, recovery = sign_eip712_via_baw(wallet_request, "auth")
    verify_payload = {"wallet": wallet, "challenge": challenge, "signature": signature}
    if recovery is not None:
        verify_payload["signatureRecovery"] = recovery
    ver = post_json_with_backoff(AUTH_VERIFY, verify_payload, label="auth-verify")
    token = ver.get("token") or ver.get("accessToken") or ver.get("bearerToken") or ver.get("jwt")
    if not token:
        raise RuntimeError(f"auth verify returned no token; keys={sorted(ver.keys())}")
    client.token = token
    log("auth", "MCP auth ok (token held in memory only)")
    return True


# ---------------------------------------------------------------- on-chain verify
def eth_code(to):
    return rpc_first("eth_getCode", [to, "latest"])


def verify_deployment(signer_addr):
    checks = [
        ("FreeMint.nft()", FREEMINT, sel("nft()"), "address", NFT),
        ("NFT.minter()", NFT, sel("minter()"), "address", FREEMINT),
        ("FreeMint.agentGate()", FREEMINT, sel("agentGate()"), "address", AGENTGATE),
        ("FreeMint.signer()", FREEMINT, sel("signer()"), "address", signer_addr),
        ("FreeMint.paused()", FREEMINT, sel("paused()"), "bool", False),
        ("NFT.MAX_PER_WALLET()", NFT, sel("MAX_PER_WALLET()"), "uint", 2),
        ("NFT.MAX_SUPPLY()", NFT, sel("MAX_SUPPLY()"), "uint", 7777),
        ("AgentGate.registry()", AGENTGATE, sel("registry()"), "address", REGISTRY),
        ("AgentGate.identityPolicy()", AGENTGATE, sel("identityPolicy()"), "bytes32",
         "0x1935aa6dfd268155998a972ad6120bf5f28804ca25470b619b52309ac2dac94c"),
    ]
    for name, to, data, kind, expected in checks:
        raw = eth_call(to, data)
        if kind == "address":
            actual = dec_address(raw)
            ok = actual.lower() == expected.lower()
        elif kind == "bool":
            actual = dec_bool(raw)
            ok = actual == expected
        elif kind == "uint":
            actual = dec_uint(raw)
            ok = actual == expected
        else:
            actual = dec_bytes32(raw)
            ok = actual.lower() == expected.lower()
        log("onchain", f"{name} = {actual} expected {expected} -> {'OK' if ok else 'FAIL'}")
        if not ok:
            raise RuntimeError(f"on-chain verification FAILED: {name} = {actual}, expected {expected}")
    for name, addr in (("FreeMint", FREEMINT), ("NFT", NFT), ("AgentGate", AGENTGATE)):
        code = eth_code(addr)
        if not code or code == "0x":
            raise RuntimeError(f"{name} contract has empty code at {addr}")
        log("onchain", f"{name} code present ({len(code)} hex chars)")


def verify_identity_onchain(agent_id_decimal):
    """Returns (minted_by_wallet, total_supply). Raises on hard mismatch."""
    agent_int = int(agent_id_decimal)
    agent_bytes32 = "0x" + format(agent_int, "064x")
    # handleOf: try registry, then AgentGate. If neither exposes it, note the
    # gap and rely on ownerOf + isAuthorized (reported in the final report).
    handle_ok = None
    for contract in (REGISTRY, AGENTGATE):
        try:
            raw = eth_call(contract, sel("handleOf(address)") + addr_pad(WALLET))
            got = dec_bytes32(raw)
            # handleOf returns the raw handle as ASCII bytes32 ("leviathan",
            # right-padded), NOT the keccak hash. The agentId IS the hash:
            # agentId == keccak256("leviathan") (verified 2026-10-27). So
            # check BOTH: decoded handle == "leviathan" AND
            # keccak256(decoded handle) == agentId. Comparing the ASCII
            # bytes32 directly to the hash bytes32 was the run-5 bug.
            try:
                decoded = bytes.fromhex(got[2:]).rstrip(b"\x00").decode("ascii")
            except Exception:
                decoded = ""
            hash_ok = (keccak256(decoded.encode()).hex() == agent_bytes32[2:]) if decoded else False
            handle_ok = (decoded == EXPECTED_HANDLE) and hash_ok
            log("onchain", f"handleOf via {contract} = {got} decoded={decoded!r} keccak==agentId={hash_ok} -> {'OK' if handle_ok else 'FAIL'}")
            break
        except Exception as e:
            log("onchain", f"handleOf via {contract} unavailable ({type(e).__name__})")
            continue
    if handle_ok is False:
        raise RuntimeError("handleOf(wallet) does not match agentId")
    if handle_ok is None:
        log("onchain", "handleOf not exposed on registry/AgentGate; continuing on ownerOf+isAuthorized (gap noted)")
    owner_raw = eth_call(REGISTRY, sel("ownerOf(uint256)") + format(agent_int, "064x"))
    owner = dec_address(owner_raw)
    log("onchain", f"ownerOf(agentId) = {owner} -> {'OK' if owner.lower() == WALLET.lower() else 'FAIL'}")
    if owner.lower() != WALLET.lower():
        raise RuntimeError("ownerOf(agentId) is not the wallet")
    auth_ok = None
    for sig in ("isAuthorized(bytes32,address)", "isAuthorized(uint256,address)"):
        try:
            arg0 = agent_bytes32[2:] if sig.startswith("isAuthorized(bytes32") else format(agent_int, "064x")
            raw = eth_call(AGENTGATE, sel(sig) + arg0 + addr_pad(WALLET))
            auth_ok = dec_bool(raw)
            log("onchain", f"{sig} = {auth_ok}")
            break
        except Exception as e:
            log("onchain", f"{sig} unavailable ({type(e).__name__})")
            continue
    if auth_ok is not True:
        raise RuntimeError("AgentGate.isAuthorized(agentId, wallet) is not true")
    minted_raw = eth_call(NFT, sel("mintedByWallet(address)") + addr_pad(WALLET))
    minted = dec_uint(minted_raw)
    supply_raw = eth_call(NFT, sel("totalSupply()"))
    supply = dec_uint(supply_raw)
    log("onchain", f"mintedByWallet = {minted}, totalSupply = {supply}")
    return minted, supply

# ---------------------------------------------------------------- attempt
def find_uuid_candidate(resp, idempotency_key):
    import re
    uuid_re = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    for key in ("attemptId", "attempt_id", "id", "uuid"):
        v = resp.get(key)
        if isinstance(v, str) and uuid_re.match(v):
            return v
    return None


def keccak_uuid_hex(uuid_str):
    return "0x" + keccak256(uuid_str.encode("utf-8")).hex()


def parse_typed_data_request(wallet_request):
    """Return (typed_dict, request_wallet, raw_string)."""
    if isinstance(wallet_request, str):
        wr_obj = json.loads(wallet_request)
        raw = wallet_request
    else:
        wr_obj = wallet_request
        raw = json.dumps(wallet_request)
    params = wr_obj.get("params", [])
    if len(params) != 2:
        raise RuntimeError("walletRequest params are not [wallet, typedData]")
    typed = json.loads(params[1]) if isinstance(params[1], str) else params[1]
    return typed, params[0], raw


def prepare_and_start(client, wallet, agent_id_decimal):
    """Returns dict with uuid, capability, version, benchmark, fragmentCount,
    toolBudget, deadlineSeconds, activation_time."""
    idem = str(uuid.uuid4())
    try:
        prep = retry_with_backoff(
            lambda: client.call_tool("prepare_attempt", {
                "wallet": wallet, "beneficiary": wallet,
                "agentId": agent_id_decimal, "idempotencyKey": idem,
            }),
            attempts=60, server_response_only=True,
        )
    except ToolError as e:
        msg = str(e)
        if "pending" in msg.lower() or "existing" in msg.lower() or "already" in msg.lower():
            log("attempt", "prepare reports an existing/pending attempt; recovering via attempt_status")
            st = None
            for args in ({"wallet": wallet}, {"attemptId": idem}):
                try:
                    st = client.call_tool("attempt_status", args)
                    break
                except Exception:
                    continue
            if not st:
                raise RuntimeError("could not recover pending attempt status")
            log("attempt", f"recovered attempt status keys: {sorted(st.keys())}")
            raise RuntimeError("pending attempt recovered; refusing to create a second attempt (manual resume needed)")
        raise
    log("attempt", f"prepare keys: {sorted(prep.keys())}")
    uuid_str = find_uuid_candidate(prep, idem)
    start_auth = prep.get("startAuthorization") or prep.get("start_authorization") or {}
    start_wr = prep.get("startWalletRequest") or prep.get("start_wallet_request")
    if start_wr is None:
        raise RuntimeError("prepare response has no startWalletRequest")
    typed, req_wallet, _raw = parse_typed_data_request(start_wr)
    domain = typed.get("domain", {}) or {}
    tmsg = typed.get("message", {}) or {}
    # Determine the UUID whose keccak matches the authorization attemptId.
    auth_attempt = tmsg.get("attemptId") or start_auth.get("attemptId") or start_auth.get("attempt_id")
    candidates = [c for c in (uuid_str, idem) if c]
    chosen = None
    if auth_attempt:
        for cand in candidates:
            if keccak_uuid_hex(cand).lower() == str(auth_attempt).lower():
                chosen = cand
                break
        if chosen is None:
            raise RuntimeError("no UUID candidate matches the start authorization attemptId hash")
    else:
        chosen = uuid_str or idem
    uuid_str = chosen
    checks = {
        "domain_name": domain.get("name") == "NONCE Free Mint",
        "domain_version": str(domain.get("version")) == "1",
        "domain_chain": int(domain.get("chainId", 0)) == 56,
        "domain_contract": str(domain.get("verifyingContract", "")).lower() == FREEMINT.lower(),
        "primaryType": typed.get("primaryType") == "StartAuthorization",
        "wallet": str(tmsg.get("wallet", "")).lower() == wallet.lower()
        and str(req_wallet).lower() == wallet.lower(),
        "attempt_hash": (str(tmsg.get("attemptId", "")).lower() == keccak_uuid_hex(uuid_str).lower())
        if tmsg.get("attemptId") else True,
    }
    log("attempt", "startAuthorization checks: " + ", ".join(f"{k}={'OK' if v else 'FAIL'}" for k, v in checks.items()))
    failed = [k for k, v in checks.items() if not v]
    if failed:
        raise RuntimeError(f"start authorization verification FAILED on: {failed}")
    # Sign the exact start wallet request.
    wr_str = start_wr if isinstance(start_wr, str) else json.dumps(start_wr)
    signature, recovery = sign_eip712_via_baw(wr_str, "start")
    start_args = {"attemptId": uuid_str, "signature": signature}
    if recovery is not None:
        start_args["signatureRecovery"] = recovery
    # start_attempt is retried on 429 with the SAME signature: the server
    # explicitly answers 429 with "keep the same attempt", and a 429 means
    # the call was not executed, so retrying cannot duplicate activation.
    # SESSION_RENEWAL_REQUIRED is handled inside by renewing MCP auth once.
    def _start():
        try:
            return client.call_tool("start_attempt", start_args, timeout=60)
        except ToolError as e:
            if "SESSION_RENEWAL_REQUIRED" in str(e):
                log("attempt", "start_attempt SESSION_RENEWAL_REQUIRED; renewing MCP auth and retrying same attempt")
                authenticate_mcp(client, wallet)
                return client.call_tool("start_attempt", start_args, timeout=60)
            raise

    started = retry_with_backoff(_start, attempts=60, server_response_only=True)
    log("attempt", f"start_attempt keys: {sorted(started.keys())}")
    info = {
        "uuid": uuid_str,
        "capability": started.get("capability") or prep.get("capability"),
        "version": started.get("version") or prep.get("version"),
        "benchmark": started.get("benchmark") or prep.get("benchmark"),
        "fragmentCount": started.get("fragmentCount") or prep.get("fragmentCount"),
        "toolBudget": started.get("toolBudget") or prep.get("toolBudget"),
        "deadlineSeconds": started.get("deadlineSeconds") or prep.get("deadlineSeconds"),
        "activation_time": time.time(),
    }
    bench = info["benchmark"]
    bench_name = bench if isinstance(bench, str) else (bench or {}).get("name") or (bench or {}).get("profile") or (bench or {}).get("version")
    log("attempt", f"activated version={info['version']} benchmark={bench_name} fragments={info['fragmentCount']} budget={info['toolBudget']} deadline={info['deadlineSeconds']}s")
    if not info["capability"]:
        log("attempt", "WARNING: no capability returned; fragment calls may fail")
    return info


# ---------------------------------------------------------------- solve
def normalize_clauses(fragment):
    """Extract a list of clauses (each a list of ints) from a fragment."""
    data = fragment
    if isinstance(data, dict):
        for key in ("clauses", "fragment", "data", "content"):
            if key in data:
                data = data[key]
                break
    if isinstance(data, dict) and "clauses" in data:
        data = data["clauses"]
    if not isinstance(data, list):
        raise RuntimeError(f"unrecognized fragment shape: {str(fragment)[:200]}")
    clauses = []
    for c in data:
        if isinstance(c, list):
            clauses.append([int(x) for x in c])
        elif isinstance(c, str):
            clauses.append([int(x) for x in c.replace(",", " ").split()])
        elif isinstance(c, dict) and "literals" in c:
            clauses.append([int(x) for x in c["literals"]])
        else:
            raise RuntimeError(f"unrecognized clause shape: {str(c)[:200]}")
    return clauses


def profile_var_count(benchmark, max_literal):
    name = ""
    if isinstance(benchmark, str):
        name = benchmark
    elif isinstance(benchmark, dict):
        name = str(benchmark.get("name") or benchmark.get("profile") or benchmark.get("version") or "")
        if benchmark.get("variableCount"):
            return int(benchmark["variableCount"]), name
        if benchmark.get("numVars"):
            return int(benchmark["numVars"]), name
    import re
    m = re.search(r"(\d{3,5})", name)
    if m:
        return int(m.group(1)), name
    return max_literal, name


def _portfolio_worker(solver_name, clauses, n_vars, conn):
    """Run ONE CDCL solver in a child process.

    Sends exactly one message over conn: ("sat", name, assignment) only if
    the model is locally verified against EVERY clause, ("unsat", name,
    None) if the solver proves unsatisfiability, ("badmodel", name, None)
    if a returned model fails verification (never trusted), or ("error",
    name, message) on exception. The parent never submits an unverified
    assignment.
    """
    try:
        from pysat.solvers import Cadical153, Glucose4, MapleCM, Minisat22

        cls = {"Cadical153": Cadical153, "MapleCM": MapleCM,
               "Glucose4": Glucose4, "Minisat22": Minisat22}[solver_name]
        with cls() as solver:
            for c in clauses:
                solver.add_clause(c)
            sat = solver.solve()
            if sat:
                model = solver.get_model()
                pos = set(x for x in model if x > 0)
                assignment = "".join("1" if (k + 1) in pos else "0" for k in range(n_vars))
                if verify_assignment(clauses, assignment):
                    conn.send(("sat", solver_name, assignment))
                else:
                    conn.send(("badmodel", solver_name, None))
            else:
                conn.send(("unsat", solver_name, None))
    except Exception as e:
        try:
            conn.send(("error", solver_name, str(e)[:300]))
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _run_portfolio_pair(clauses, n_vars, names, window_seconds):
    """Run one pair of solvers for up to window_seconds.

    Returns (assignment_or_None, status) with status in sat/unsat/timeout/
    error:<detail>. Only a locally verified assignment is returned as sat.
    """
    import multiprocessing as mp

    ctx = mp.get_context("fork")
    procs = []
    conns = []
    for name in names:
        parent_conn, child_conn = ctx.Pipe(duplex=False)
        p = ctx.Process(target=_portfolio_worker, args=(name, clauses, n_vars, child_conn), daemon=True)
        p.start()
        child_conn.close()
        procs.append(p)
        conns.append((name, parent_conn))
    deadline = time.time() + window_seconds
    unsat_count = 0
    errors = []
    result = (None, "timeout")
    try:
        while time.time() < deadline:
            remaining = deadline - time.time()
            ready = mp.connection.wait([c for _, c in conns], timeout=min(5, remaining))
            if not ready:
                if not any(p.is_alive() for p in procs):
                    break
                continue
            for conn in ready:
                try:
                    kind, name, payload = conn.recv()
                except EOFError:
                    continue
                if kind == "sat":
                    log("solve", f"portfolio winner: {name}")
                    return payload, "sat"
                if kind == "unsat":
                    unsat_count += 1
                elif kind in ("error", "badmodel"):
                    errors.append(f"{name}:{payload or kind}")
                if unsat_count + len(errors) >= len(names):
                    if unsat_count == len(names):
                        return None, "unsat"
                    return None, "error:" + "; ".join(errors)
            if not any(p.is_alive() for p in procs):
                # Drain any message that arrived just as workers exited.
                for _name, conn in conns:
                    while conn.poll():
                        try:
                            kind, name, payload = conn.recv()
                        except EOFError:
                            break
                        if kind == "sat":
                            log("solve", f"portfolio winner: {name}")
                            return payload, "sat"
                break
        if unsat_count == len(names):
            result = (None, "unsat")
        elif errors:
            result = (None, "error:" + "; ".join(errors))
        elif not any(p.is_alive() for p in procs):
            result = (None, "error:worker exited without result")
        else:
            result = (None, "timeout")
        return result
    finally:
        for p in procs:
            if p.is_alive():
                p.terminate()
        for p in procs:
            p.join(timeout=5)
        for _name, conn in conns:
            try:
                conn.close()
            except Exception:
                pass


def solve_sat(clauses, n_vars, budget_seconds):
    """TURBO portfolio solve; returns (assignment, status) with status
    exactly "sat" on a locally verified assignment (callers depend on this
    string), else "unsat"/"timeout"/"error:<detail>".

    2 worker processes on 2 CPUs. Window 1 (first 60% of budget):
    Cadical153 + MapleCM. If the pair stalls (no result in window 1),
    window 2 (remaining budget): Glucose4 + Minisat22. A single driver
    run is one attempt; repeating failed attempts is the caller's job
    (re-invoke the driver with a fresh UUID).
    """
    w1 = max(30, int(budget_seconds * 0.6))
    log("solve", f"turbo portfolio window1 Cadical153+MapleCM for {w1}s of {budget_seconds}s budget")
    assignment, status = _run_portfolio_pair(clauses, n_vars, ["Cadical153", "MapleCM"], w1)
    if assignment is not None:
        return assignment, "sat"
    if status == "unsat":
        return None, "unsat"
    remaining = budget_seconds - w1
    if remaining >= 30:
        log("solve", f"turbo portfolio window2 Glucose4+Minisat22 for {remaining}s (window1: {status})")
        assignment, status = _run_portfolio_pair(clauses, n_vars, ["Glucose4", "Minisat22"], remaining)
        if assignment is not None:
            return assignment, "sat"
        if status == "unsat":
            return None, "unsat"
        return None, status
    return None, status


def verify_assignment(clauses, assignment):
    for c in clauses:
        ok = False
        for lit in c:
            v = assignment[abs(lit) - 1]
            if (lit > 0 and v == "1") or (lit < 0 and v == "0"):
                ok = True
                break
        if not ok:
            return False
    return True


def solve_route_14(fragments):
    """Held-Karp DP for a 14-node route attempt. Returns route list or None."""
    import itertools
    cost = None
    constraints = []
    target = None
    for frag in fragments:
        if isinstance(frag, dict):
            if "cost" in frag or "costs" in frag or "matrix" in frag:
                cost = frag.get("cost") or frag.get("costs") or frag.get("matrix")
            if "constraints" in frag:
                constraints.extend(frag["constraints"])
            if "targetCost" in frag:
                target = frag["targetCost"]
    if cost is None:
        return None
    n = len(cost)
    INF = float("inf")
    dp = {}
    parent = {}
    dp[(1 << 0, 0)] = 0
    for mask in range(1 << n):
        if not (mask & 1):
            continue
        for last in range(n):
            if (mask, last) not in dp:
                continue
            for nxt in range(n):
                if mask & (1 << nxt):
                    continue
                nmask = mask | (1 << nxt)
                nc = dp[(mask, last)] + cost[last][nxt]
                if nc < dp.get((nmask, nxt), INF):
                    dp[(nmask, nxt)] = nc
                    parent[(nmask, nxt)] = last
    full = (1 << n) - 1
    best_last, best = None, INF
    for last in range(n):
        if last == 0:
            continue
        c = dp.get((full, last), INF) + cost[last][0]
        if c < best:
            best, best_last = c, last
    if best_last is None:
        return None
    route = [best_last]
    mask, last = full, best_last
    while last != 0:
        prev = parent[(mask, last)]
        route.append(prev)
        mask &= ~(1 << last)
        last = prev
    route.reverse()
    # route starts at 0, visits all once; submit without repeating final 0
    if target is not None and best != target:
        return None
    return route

# ---------------------------------------------------------------- mint + verify
def fetch_sourcify_abi(address):
    for match in ("full_match", "partial_match"):
        url = f"https://repo.sourcify.dev/contracts/{match}/56/{address}/metadata.json"
        try:
            resp = requests.get(url, timeout=20)
            if resp.status_code != 200:
                continue
            meta = resp.json()
            abi = (meta.get("output") or {}).get("abi") or meta.get("abi")
            if abi:
                log("abi", f"Sourcify {match} ABI for {address} ({len(abi)} entries)")
                return abi
        except Exception as e:
            log("abi", f"Sourcify {match} failed: {type(e).__name__}")
    try:
        resp = requests.get(
            "https://api.bscscan.com/api",
            params={"module": "contract", "action": "getabi", "address": address},
            timeout=20,
        )
        obj = resp.json()
        if obj.get("status") == "1":
            abi = json.loads(obj["result"])
            log("abi", f"BscScan ABI for {address} ({len(abi)} entries)")
            return abi
        log("abi", f"BscScan getabi not ok: {str(obj)[:200]}")
    except Exception as e:
        log("abi", f"BscScan getabi failed: {type(e).__name__}")
    return None


def canonical_type(param):
    t = param["type"]
    if t == "tuple":
        inner = ",".join(canonical_type(c) for c in param["components"])
        return f"({inner})"
    if t.startswith("tuple["):
        inner = ",".join(canonical_type(c) for c in param["components"])
        return f"({inner})" + t[len("tuple"):]
    return t


def fn_signature(fn_abi):
    return f"{fn_abi['name']}(" + ",".join(canonical_type(p) for p in fn_abi.get("inputs", [])) + ")"


def decode_mint_tx(abi, data_hex):
    """Return (fn_abi, decoded_args). Raises if selector unknown."""
    from eth_abi import decode as abi_decode
    data = bytes.fromhex(data_hex.replace("0x", ""))
    selector = "0x" + data[:4].hex()
    for fn in abi:
        if fn.get("type") != "function" or fn.get("name") != "mint":
            continue
        if sel(fn_signature(fn)).lower() == selector.lower():
            types = [canonical_type(p) for p in fn.get("inputs", [])]
            args = abi_decode(types, data[4:])
            return fn, args
    raise RuntimeError(f"mint selector {selector} not found in FreeMint ABI")


def event_topic0(ev_abi):
    return "0x" + keccak256(fn_signature(ev_abi).encode()).hex()


def decode_abi_string(data_hex):
    raw = bytes.fromhex(data_hex.replace("0x", ""))
    if len(raw) < 64:
        raise RuntimeError("tokenURI return data too short")
    length = int.from_bytes(raw[32:64], "big")
    return raw[64:64 + length].decode("utf-8", errors="replace")


def wait_receipt(tx_hash, timeout=300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rec = eth_receipt(tx_hash)
        if rec:
            return rec
        time.sleep(10)
    raise RuntimeError(f"no receipt for {tx_hash} after {timeout}s")


def wait_confirmations(receipt, needed=12, timeout=600):
    block_no = int(receipt["blockNumber"], 16)
    deadline = time.time() + timeout
    while time.time() < deadline:
        latest = eth_block_number()
        if latest >= block_no + needed:
            return latest
        time.sleep(10)
    raise RuntimeError(f"confirmations < {needed} after {timeout}s")


def find_transfer_token_id(receipt, wallet):
    topic0 = "0x" + keccak256(b"Transfer(address,address,uint256)").hex()
    zero_pad = "0" * 64
    wallet_pad = addr_pad(wallet)
    found = []
    for lg in receipt.get("logs", []):
        topics = lg.get("topics", [])
        if len(topics) >= 4 and topics[0].lower() == topic0.lower():
            if topics[1].lower().endswith(zero_pad[-64:]) and topics[1].lower() == "0x" + zero_pad:
                pass
            if topics[1] == "0x" + "0" * 64 and topics[2].lower() == "0x" + wallet_pad:
                found.append(int(topics[3], 16))
    return found


# ---------------------------------------------------------------- main
def main():
    report = {
        "timeline": [],
        "attemptId": None,
        "benchmark": {},
        "fragmentsCollected": 0,
        "solveResult": {},
        "outcome": "NOT_STARTED",
        "stoppedStep": None,
        "evidence": None,
        "gaps": [],
        "mint": None,
    }

    def phase(name):
        t = {"phase": name, "started": wib_now(), "status": "running"}
        report["timeline"].append(t)
        return t

    def done(t, status):
        t["ended"] = wib_now()
        t["status"] = status

    try:
        # ---- Phase 0: wallet checks
        t = phase("wallet")
        st = run_baw(["wallet", "status", "--json"])
        if not baw_ok(st) or st["data"].get("status") != "CONNECTED":
            raise RuntimeError(f"wallet not CONNECTED: {json.dumps(st)[:300]}")
        addrs = run_baw(["wallet", "address", "--json"])
        chain56 = [a for a in addrs["data"]["addresses"] if a.get("binanceChainId") == "56"]
        if not chain56 or chain56[0]["address"].lower() != WALLET.lower():
            raise RuntimeError("chain 56 address mismatch")
        settings = run_baw(["wallet", "settings", "--json"])
        dev = (settings["data"] or {}).get("devMode", {})
        if not dev.get("enabled"):
            raise RuntimeError("devMode.enabled is false")
        agent = run_baw(["wallet", "agent-id", "--json"])
        if not agent["data"].get("claimed") or agent["data"].get("handle") != EXPECTED_HANDLE:
            raise RuntimeError(f"Agent ID not claimed as {EXPECTED_HANDLE}: {json.dumps(agent)[:300]}")
        lock = run_baw(["wallet", "tx-lock", "--binanceChainId", "56", "--json"])
        log("wallet", f"status CONNECTED, devMode enabled until {dev.get('expiresAt')}, agent {agent['data'].get('agentId')}, tx-lock {lock['data'].get('status')}")
        if lock["data"].get("status") == "LOCKED":
            for _ in range(8):
                time.sleep(15)
                lock = run_baw(["wallet", "tx-lock", "--binanceChainId", "56", "--json"])
                if lock["data"].get("status") == "UNLOCKED":
                    break
            if lock["data"].get("status") == "LOCKED":
                raise RuntimeError("wallet tx-lock still LOCKED after 2 min")
        done(t, "ok")

        # ---- Phase 1: protocol_info
        t = phase("protocol_info")
        client = MCPClient(MCP_URL)
        info = retry_with_backoff(lambda: client.call_tool("protocol_info", {}), attempts=60)
        log("protocol_info", f"keys: {sorted(info.keys())}")
        admission = info.get("admission")
        signer_addr = info.get("signer")
        if admission != "open":
            done(t, "stopped")
            report["outcome"] = "STOPPED"
            report["stoppedStep"] = "protocol_info"
            report["evidence"] = f"admission={admission!r} (not open); info keys={sorted(info.keys())}"
            print("\n===== FINAL_REPORT_JSON =====")
            print(json.dumps(report, indent=2))
            return 0
        for key, expected in (("mintPrice", "0"), ("failureFee", "0"), ("maxMintsPerWallet", 2), ("supplyCap", 7777)):
            if key in info and str(info[key]) != str(expected):
                raise RuntimeError(f"protocol_info {key}={info[key]!r}, expected {expected!r}")
        if not signer_addr:
            raise RuntimeError("protocol_info returned no signer")
        log("protocol_info", f"admission=open signer={signer_addr}")
        done(t, "ok")

        # ---- Phase 2: MCP auth
        t = phase("auth")
        authenticate_mcp(client, WALLET)
        done(t, "ok")

        # ---- Phase 3: on-chain deployment verification
        t = phase("onchain_verify")
        verify_deployment(signer_addr)
        done(t, "ok")

        # ---- Phase 4: identity + quota
        t = phase("identity_quota")
        ident = retry_with_backoff(lambda: client.call_tool("agent_identity", {"wallet": WALLET}), attempts=60)
        log("identity", f"agent_identity keys: {sorted(ident.keys())}")
        # agent_identity returns a DISCOVERY object, not a flat identity:
        # {identities: [{agentId, handle, owner, authorizedWallet, ...}],
        #  selectedAgentId, registry, chainId, discoveryComplete, ...}.
        # The old flat parser read handle/agentId at top level and always got
        # ''/None (run 4 stopped here); the real data lives in identities[].
        idents = ident.get("identities") or []
        selected = ident.get("selectedAgentId")
        log("identity", f"discoveryComplete={ident.get('discoveryComplete')} identities={len(idents)} selectedAgentId={selected}")
        entry = None
        if selected:
            for e in idents:
                if isinstance(e, dict) and str(e.get("agentId")) == str(selected):
                    entry = e
                    break
        if entry is None and idents:
            entry = idents[0] if isinstance(idents[0], dict) else None
        if entry is None:
            raise RuntimeError("agent_identity returned no identities")
        handle = entry.get("handle") or entry.get("name") or ""
        handle_base = str(handle).removesuffix(".ai") if isinstance(handle, str) else ""
        if handle_base != EXPECTED_HANDLE:
            raise RuntimeError(f"agent_identity handle {handle!r} is not {EXPECTED_HANDLE}")
        if entry.get("owner") and str(entry["owner"]).lower() != WALLET.lower():
            raise RuntimeError(f"agent_identity owner {entry['owner']!r} != wallet")
        if entry.get("authorizedWallet") and str(entry["authorizedWallet"]).lower() != WALLET.lower():
            raise RuntimeError(f"agent_identity authorizedWallet {entry['authorizedWallet']!r} != wallet")
        agent_id_raw = entry.get("agentId") or entry.get("agent_id") or entry.get("id") or selected
        if agent_id_raw is None:
            raise RuntimeError("agent_identity returned no agentId")
        agent_id_decimal = str(int(str(agent_id_raw), 0)) if str(agent_id_raw).startswith("0x") else str(agent_id_raw)
        minted_before, supply_before = verify_identity_onchain(agent_id_decimal)
        if minted_before >= 2:
            raise RuntimeError(f"mintedByWallet={minted_before}: no remaining lifetime mints")
        if supply_before >= 7777:
            raise RuntimeError(f"totalSupply={supply_before}: collection sold out")
        ws = retry_with_backoff(lambda: client.call_tool("wallet_status", {"wallet": WALLET}), attempts=60)
        log("identity", f"wallet_status keys: {sorted(ws.keys())}")
        done(t, "ok")

        # ---- Phase 5: prepare + start
        t = phase("prepare_start")
        attempt = prepare_and_start(client, WALLET, agent_id_decimal)
        report["attemptId"] = attempt["uuid"]
        report["benchmark"] = {
            "version": attempt["version"],
            "benchmark": attempt["benchmark"] if isinstance(attempt["benchmark"], str) else json.dumps(attempt["benchmark"])[:300],
            "fragmentCount": attempt["fragmentCount"],
            "toolBudget": attempt["toolBudget"],
            "deadlineSeconds": attempt["deadlineSeconds"],
        }
        done(t, "ok")

        # ---- Phase 6: fragments, solve, submit
        t = phase("fragments_solve_submit")
        frag_count = attempt["fragmentCount"]
        budget = attempt["toolBudget"] or frag_count
        deadline = attempt["deadlineSeconds"] or 600
        if not frag_count:
            raise RuntimeError("attempt returned no fragmentCount")
        capability = attempt["capability"]
        fragments = []
        reads = 0
        for i in range(frag_count):
            if reads >= budget and len(fragments) < frag_count:
                raise RuntimeError(f"fragment read budget {budget} exhausted at {len(fragments)}/{frag_count}")
            frag = client.call_tool("inspect_fragment", {"attemptId": attempt["uuid"], "capability": capability, "fragmentId": i}, timeout=60)
            reads += 1
            clauses = normalize_clauses(frag)
            fragments.append(clauses)
            log("fragments", f"fragment {i}: {len(clauses)} clauses (reads {reads}/{budget})")
        report["fragmentsCollected"] = len(fragments)
        bench_name = report["benchmark"]["benchmark"]
        is_route = "route" in str(bench_name).lower()
        elapsed = time.time() - attempt["activation_time"]
        remaining = deadline - elapsed
        log("solve", f"deadline {deadline}s, elapsed {elapsed:.0f}s, remaining {remaining:.0f}s")
        submit_payload = None
        if is_route:
            route = solve_route_14([{"clauses": c} for c in fragments])
            if route is not None:
                submit_payload = {"route": route}
                report["solveResult"] = {"status": "route_found", "verified": True}
            else:
                report["solveResult"] = {"status": "route_not_found", "verified": False}
        else:
            all_clauses = [c for frag in fragments for c in frag]
            max_lit = max((abs(l) for c in all_clauses for l in c), default=0)
            n_vars, prof = profile_var_count(attempt["benchmark"], max_lit)
            log("solve", f"profile={prof} vars={n_vars} clauses={len(all_clauses)}")
            # CNF export bridge (external many-core engine): dump DIMACS the
            # moment fragments are complete, so soal.cnf can leave this VM
            # immediately for an external solve.py run. Additive only: it
            # does not change local solving, verification, or submission.
            try:
                _cnf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs", f"soal-{attempt['uuid']}.cnf")
                with open(_cnf_path, "w") as _f:
                    _f.write(f"p cnf {n_vars} {len(all_clauses)}\n")
                    for _c in all_clauses:
                        _f.write(" ".join(str(_l) for _l in _c) + " 0\n")
                log("solve", f"soal.cnf exported: {_cnf_path}")
            except Exception as _e:
                log("solve", f"soal.cnf export failed (local solve continues): {_e}")
            if max_lit > n_vars:
                raise RuntimeError(f"max literal {max_lit} exceeds var count {n_vars}")
            solve_budget = max(30, remaining - 120)
            assignment, status = solve_sat(all_clauses, n_vars, solve_budget)
            if status == "sat" and assignment is not None and verify_assignment(all_clauses, assignment):
                submit_payload = {"assignment": assignment}
                report["solveResult"] = {"status": "sat", "verified": True, "assignmentLength": len(assignment)}
            else:
                report["solveResult"] = {"status": status, "verified": False, "assignmentLength": len(assignment) if assignment else 0}
                log("solve", f"no verified solution ({status}); will NOT submit")
        if submit_payload is None:
            done(t, "no_submit")
            report["outcome"] = "EXPIRED_NO_SUBMIT"
            report["stoppedStep"] = "solve"
            report["evidence"] = f"solve result {report['solveResult']}; no verified assignment, nothing submitted (no fee charged)"
            print("\n===== FINAL_REPORT_JSON =====")
            print(json.dumps(report, indent=2))
            return 0
        try:
            sub = client.call_tool("submit_artifact", {
                "attemptId": attempt["uuid"], "capability": capability,
                "artifact": submit_payload, "nonce": "0",
            }, timeout=120)
        except (ToolError, Exception) as e:
            log("submit", f"submit response uncertain ({type(e).__name__}); checking attempt_status before any retry")
            try:
                st = client.call_tool("attempt_status", {"attemptId": attempt["uuid"]}, timeout=60)
                log("submit", f"attempt_status after uncertain submit: keys={sorted(st.keys())}")
                sub = st
            except Exception as e2:
                raise RuntimeError(f"submit uncertain and attempt_status failed: {e2}")
        log("submit", f"submit keys: {sorted(sub.keys()) if isinstance(sub, dict) else type(sub)}")
        submit_status = ""
        if isinstance(sub, dict):
            submit_status = str(sub.get("status") or sub.get("result") or sub.get("outcome") or "")
        if "VERIFIED_WIN" not in submit_status.upper():
            done(t, "not_win")
            report["outcome"] = "NOT_WIN"
            report["stoppedStep"] = "submit_artifact"
            report["evidence"] = f"submit status={submit_status!r}; keys={sorted(sub.keys()) if isinstance(sub, dict) else ''}"
            print("\n===== FINAL_REPORT_JSON =====")
            print(json.dumps(report, indent=2))
            return 0
        log("submit", "VERIFIED_WIN")
        done(t, "win")

        # ---- Phase 7: mint after verified win
        t = phase("mint")
        mt = client.call_tool("mint_transaction", {"attemptId": attempt["uuid"], "capability": capability}, timeout=120)
        log("mint", f"mint_transaction keys: {sorted(mt.keys()) if isinstance(mt, dict) else type(mt)}")
        authz = mt.get("authorization") or mt.get("mintAuthorization") or {}
        receipt_obj = mt.get("receipt") or authz.get("receipt") or {}
        tx_obj = mt.get("transaction") or mt.get("tx") or {}
        sig = mt.get("signature")
        exp_hash = authz.get("receiptHash") or mt.get("receiptHash")
        # verify authorization fields
        if str(authz.get("attemptId", "")).lower() != keccak_uuid_hex(attempt["uuid"]).lower():
            raise RuntimeError("mint authorization attemptId does not match UUID hash")
        if str(authz.get("wallet", "")).lower() != WALLET.lower():
            raise RuntimeError("mint authorization wallet mismatch")
        auth_agent = authz.get("agentId")
        if auth_agent is not None and str(int(str(auth_agent), 0)) != agent_id_decimal:
            raise RuntimeError("mint authorization agentId mismatch")
        if receipt_obj.get("valid") is not True:
            raise RuntimeError("mint receipt.valid is not true")
        if str(receipt_obj.get("attemptId", "")) != attempt["uuid"]:
            raise RuntimeError("mint receipt attemptId does not match UUID")
        entropy = str(receipt_obj.get("mintEntropy", ""))
        if not (entropy.startswith("0x") and len(entropy) == 66):
            raise RuntimeError("mintEntropy is not a 32-byte hex value")
        if exp_hash:
            canon = json.dumps(receipt_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            got_hash = "0x" + keccak256(canon.encode("utf-8")).hex()
            alt = dict(receipt_obj)
            alt.pop("receiptHash", None)
            alt.pop("hash", None)
            got_hash2 = "0x" + keccak256(json.dumps(alt, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hex()
            if got_hash.lower() != str(exp_hash).lower() and got_hash2.lower() != str(exp_hash).lower():
                raise RuntimeError("receiptHash does not match canonical receipt JSON")
            log("mint", "receiptHash verified")
        exp = parse_expires_at(receipt_obj.get("expiry") or receipt_obj.get("expiresAt") or authz.get("expiry"))
        if exp is not None and exp <= time.time():
            raise RuntimeError("mint authorization expired")
        # signer verification via EIP-712 if typed data is available
        typed_mint = mt.get("typedData") or mt.get("typed_data")
        if typed_mint and sig:
            from eth_account.messages import encode_typed_data
            from eth_account import Account
            msg = encode_typed_data(full_message=typed_mint)
            recovered = Account.recover_message(msg, signature=sig)
            log("mint", f"mint authorization signer recovered, matches FreeMint.signer: {recovered.lower() == signer_addr.lower()}")
            if recovered.lower() != signer_addr.lower():
                raise RuntimeError("mint authorization signer does not match FreeMint.signer()")
        else:
            log("mint", "no typedData/signature in mint_transaction response; signer check via on-chain signer deferred to tx decode")
            report["gaps"].append("mint_transaction returned no typedData; EIP-712 signer recovery skipped")
        # decode tx with published ABI
        tx_to = tx_obj.get("to") or tx_obj.get("toAddress")
        tx_value = tx_obj.get("value", 0)
        tx_data = tx_obj.get("data") or tx_obj.get("inputData") or tx_obj.get("input")
        if not tx_data:
            raise RuntimeError("mint_transaction returned no transaction data")
        if str(tx_to).lower() != FREEMINT.lower():
            raise RuntimeError("mint tx to is not FreeMint")
        if int(str(tx_value), 0) != 0:
            raise RuntimeError("mint tx value is not 0")
        abi = fetch_sourcify_abi(FREEMINT)
        if not abi:
            raise RuntimeError("could not obtain FreeMint ABI to decode mint tx")
        fn_abi, decoded = decode_mint_tx(abi, tx_data)
        log("mint", f"mint tx decoded as {fn_signature(fn_abi)}")
        # refresh checks immediately before preview
        info2 = retry_with_backoff(lambda: client.call_tool("protocol_info", {}), attempts=3)
        if info2.get("admission") != "open":
            raise RuntimeError("admission closed before mint preview")
        minted_now, supply_now = verify_identity_onchain(agent_id_decimal)
        if minted_now != minted_before:
            raise RuntimeError(f"mintedByWallet changed before preview ({minted_before} -> {minted_now})")
        used_raw = eth_call(FREEMINT, sel("usedAttempts(bytes32)") + keccak_uuid_hex(attempt["uuid"])[2:])
        if dec_bool(used_raw):
            raise RuntimeError("usedAttempts already true before preview; refusing to send another mint")
        bal = run_baw(["wallet", "balance", "--binanceChainId", "56", "--symbol", "BNB", "--json"])
        bnb_bal = 0.0
        for item in (bal.get("data") or []):
            try:
                bnb_bal = float(item.get("balance", 0))
            except (TypeError, ValueError):
                pass
        log("mint", f"BNB balance {bnb_bal}")
        if bnb_bal < 0.0002:
            raise RuntimeError(f"BNB balance {bnb_bal} too low for gas")
        prev = run_baw(["contract-call", "preview", "--binanceChainId", "56", "--from", WALLET,
                        "--to", FREEMINT, "--value", "0", "--inputData", tx_data, "--json"], timeout=180)
        if not baw_ok(prev):
            raise RuntimeError(f"mint preview failed: {json.dumps(prev)[:600]}")
        pdata = prev["data"]
        req_id = pdata.get("requestId")
        log("mint", f"mint preview ok requireConfirmation={pdata.get('requireConfirmation')} parsedTx={json.dumps(pdata.get('parsedTx'))[:300]}")
        risks = (pdata.get("risks") or {}).get("riskDetails") or []
        if risks:
            log("mint", "mint preview risks: " + "; ".join(f"{r.get('title')}" for r in risks))
        if not req_id:
            raise RuntimeError("mint preview returned no requestId")
        exe = run_baw(["contract-call", "execute", "--requestId", req_id, "--json"], timeout=180)
        if not baw_ok(exe):
            raise RuntimeError(f"mint execute failed: {json.dumps(exe)[:600]}")
        ed = exe["data"]
        tx_hash = ed.get("txHash")
        if ed.get("status") == "PENDING_CONFIRMATION":
            log("mint", "mint PENDING_CONFIRMATION; polling tx-history for the broadcast tx (user taps in app)")
            before = set()
            hist = run_baw(["wallet", "tx-history", "--size", "20", "--json"])
            for item in (hist.get("data") or {}).get("transactions", []):
                before.add(item.get("txHash"))
            found = None
            for _ in range(40):
                time.sleep(15)
                hist = run_baw(["wallet", "tx-history", "--size", "20", "--json"])
                for item in (hist.get("data") or {}).get("transactions", []):
                    h = item.get("txHash")
                    if h and h not in before:
                        try:
                            rec = eth_receipt(h)
                        except Exception:
                            continue
                        if rec and str(rec.get("to", "")).lower() == FREEMINT.lower():
                            found = h
                            break
                if found:
                    break
            if not found:
                raise RuntimeError("mint PENDING_CONFIRMATION not resolved in 10 min; no FreeMint tx found in history")
            tx_hash = found
        if not tx_hash:
            raise RuntimeError(f"mint execute returned no txHash: {json.dumps(ed)[:300]}")
        log("mint", f"mint broadcast txHash={tx_hash}")
        done(t, "broadcast")

        # ---- Phase 8: receipt + 12 confirmations + event verification
        t = phase("verify_receipt")
        receipt = wait_receipt(tx_hash, timeout=300)
        if receipt.get("status") != "0x1":
            raise RuntimeError(f"mint receipt status is not success: {receipt.get('status')}")
        latest = wait_confirmations(receipt, needed=12, timeout=600)
        log("verify", f"receipt in block {int(receipt['blockNumber'], 16)}, latest {latest} (>=12 confirmations)")
        transfers = find_transfer_token_id(receipt, WALLET)
        if len(transfers) != 1:
            raise RuntimeError(f"expected exactly 1 zero->wallet Transfer, found {len(transfers)}")
        token_id = transfers[0]
        minted_event_ok = None
        if abi:
            for ev in abi:
                if ev.get("type") == "event" and ev.get("name") == "Minted":
                    topic0 = event_topic0(ev)
                    for lg in receipt.get("logs", []):
                        if str(lg.get("address", "")).lower() == FREEMINT.lower() and lg.get("topics", [None])[0].lower() == topic0.lower():
                            params = ev.get("inputs", [])
                            ev_token = None
                            for idx, p in enumerate(params):
                                if p.get("name") in ("tokenId", "id") and p.get("indexed"):
                                    ev_token = int(lg["topics"][idx + 1], 16)
                            if ev_token is None and lg.get("data") and len(lg["data"]) >= 66:
                                ev_token = int(lg["data"][:66], 16)
                            minted_event_ok = (ev_token == token_id)
                            log("verify", f"Minted event tokenId={ev_token} matches Transfer: {minted_event_ok}")
                    break
        owner_raw = eth_call(NFT, sel("ownerOf(uint256)") + format(token_id, "064x"))
        owner = dec_address(owner_raw)
        if owner.lower() != WALLET.lower():
            raise RuntimeError(f"ownerOf({token_id}) = {owner}, not wallet")
        minted_after, _ = verify_identity_onchain(agent_id_decimal)
        if minted_after != minted_before + 1:
            raise RuntimeError(f"mintedByWallet after mint = {minted_after}, expected {minted_before + 1}")
        used_raw = eth_call(FREEMINT, sel("usedAttempts(bytes32)") + keccak_uuid_hex(attempt["uuid"])[2:])
        if not dec_bool(used_raw):
            raise RuntimeError("usedAttempts is not true after mint")
        uri_raw = eth_call(NFT, sel("tokenURI(uint256)") + format(token_id, "064x"))
        token_uri = decode_abi_string(uri_raw)
        token_name = None
        token_image = None
        try:
            meta_url = token_uri
            if meta_url.startswith("ipfs://"):
                meta_url = "https://ipfs.io/ipfs/" + meta_url[len("ipfs://"):]
            meta = requests.get(meta_url, timeout=20).json()
            token_name = meta.get("name")
            token_image = meta.get("image")
            log("verify", f"tokenURI name={token_name} image={token_image}")
        except Exception as e:
            log("verify", f"tokenURI metadata fetch failed ({type(e).__name__}); reporting URI only")
            report["gaps"].append("tokenURI metadata fetch failed; URI reported without name/image")
        gas_used = int(receipt.get("gasUsed", "0x0"), 16)
        gas_price = receipt.get("effectiveGasPrice") or receipt.get("gasPrice") or "0x0"
        gas_bnb = gas_used * int(gas_price, 16) / 1e18
        report["mint"] = {
            "collection": "NONCE Genesis",
            "nft": NFT,
            "tokenId": token_id,
            "txHash": tx_hash,
            "gasBNB": gas_bnb,
            "gasUsed": gas_used,
            "remainingQuota": 2 - minted_after,
            "tokenURI": token_uri,
            "tokenName": token_name,
            "tokenImage": token_image,
            "explorerTx": f"https://bscscan.com/tx/{tx_hash}",
            "explorerToken": f"https://bscscan.com/token/{NFT}?a={token_id}",
        }
        done(t, "ok")
        report["outcome"] = "MINTED"
        print("\n===== FINAL_REPORT_JSON =====")
        print(json.dumps(report, indent=2))
        return 0
    except Exception as e:
        log("ERROR", f"{type(e).__name__}: {str(e)[:500]}")
        if report["outcome"] == "NOT_STARTED":
            report["outcome"] = "STOPPED"
        if not report["stoppedStep"]:
            last_phase = report["timeline"][-1]["phase"] if report["timeline"] else "unknown"
            report["stoppedStep"] = last_phase
        if not report["evidence"]:
            report["evidence"] = f"{type(e).__name__}: {str(e)[:500]}"
        for t in report["timeline"]:
            if t["status"] == "running":
                t["status"] = "failed"
                t["ended"] = wib_now()
        print("\n===== FINAL_REPORT_JSON =====")
        print(json.dumps(report, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())
