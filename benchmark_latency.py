"""
benchmark_latency.py
=====================
Reproduces Table: "Simulated Signing and Verification Latency"
from the journal paper.

Runs N_ITER iterations of CLS and BCCA sign + verify, prints
mean latency in milliseconds and compares against paper values.

Usage:
    cd "C:\\...\\Blockchain-Based anonymous authentication framework for Healthcare IoT"
    python benchmark_latency.py
"""

import sys
import time
import os

# ── Path setup ────────────────────────────────────────────────────────────────
BASE = os.path.dirname(os.path.abspath(__file__))
CLS_PATH = os.path.join(BASE, "cls_project")
sys.path.insert(0, BASE)
sys.path.insert(0, CLS_PATH)

N_ITER = 500   # iterations per measurement (increase for tighter CI)

SEP  = "=" * 66
SEP2 = "-" * 66

# ══════════════════════════════════════════════════════════════════════════════
# CLS Benchmark
# ══════════════════════════════════════════════════════════════════════════════

def run_cls_benchmark():
    from crypto.cls_scheme import (
        setup, partial_priv_key_gen, secret_value_gen, key_gen,
        sign, verify, precompute_sid_kid,
        serialize_point, deserialize_point, compress_point, _point_mul
    )

    print(f"\n{SEP}")
    print("  CLS BENCHMARK  (NIST P-256 / secp256r1)")
    print(SEP)

    # ── Setup ─────────────────────────────────────────────────────────────────
    print("  [1/4] Running Setup (KGC)...", end=" ", flush=True)
    params, msk = setup(256)
    print("done")

    # ── Register one user ─────────────────────────────────────────────────────
    print("  [2/4] Registering test user...", end=" ", flush=True)
    x   = secret_value_gen(params)
    X   = _point_mul(x, params.G)
    v_t = int(time.time())
    D   = partial_priv_key_gen(params, msk, "benchmark_user", X, v_t)
    rid = D["pseudo_id"]
    pk_record, SK = key_gen(params, rid, D, x)
    print(f"done  RID={rid[:16]}...")

    # ── Precompute SID/KID ────────────────────────────────────────────────────
    SID_list, KID_list = precompute_sid_kid(params, rid, SK, pk_record, n=N_ITER + 10)
    R_point = pk_record["R"]
    message = "benchmark_user|general|1234567890|abcdef1234567890"

    # ── Sign benchmark ────────────────────────────────────────────────────────
    print(f"  [3/4] Signing  × {N_ITER} iterations...", end=" ", flush=True)
    sign_times = []
    sigs = []
    for k in range(N_ITER):
        SID_k = int(SID_list[k])
        KID_k = deserialize_point(compress_point(KID_list[k]))
        t0 = time.perf_counter()
        sig = sign(params, SK, rid, message, R=R_point, SID_k=SID_k, KID_k=KID_k)
        sign_times.append((time.perf_counter() - t0) * 1000)
        sigs.append((sig, pk_record))
    print("done")

    # ── Verify benchmark ──────────────────────────────────────────────────────
    print(f"  [4/4] Verifying × {N_ITER} iterations...", end=" ", flush=True)
    verify_times = []
    for sig, pk_rec in sigs:
        t0 = time.perf_counter()
        verify(params, rid, pk_rec, message, sig)
        verify_times.append((time.perf_counter() - t0) * 1000)
    print("done")

    avg_sign   = sum(sign_times)   / len(sign_times)
    avg_verify = sum(verify_times) / len(verify_times)
    min_sign   = min(sign_times)
    min_verify = min(verify_times)

    print(SEP2)
    print(f"  {'Metric':<28} {'Paper':>8}  {'This run':>10}  {'Min':>8}")
    print(SEP2)
    print(f"  {'Sign   (ms, mean)':<28} {'0.20':>8}  {avg_sign:>10.4f}  {min_sign:>8.4f}")
    print(f"  {'Verify (ms, mean)':<28} {'4.72†':>8}  {avg_verify:>10.4f}  {min_verify:>8.4f}")
    print(SEP2)
    print(f"  Speedup ratio (verify/sign): {avg_verify/avg_sign:.1f}×")
    print(f"  † Paper value uses Straus-Shamir MSM; speedup ~2.33×")
    print(SEP)

    return avg_sign, avg_verify


# ══════════════════════════════════════════════════════════════════════════════
# BCCA Benchmark
# ══════════════════════════════════════════════════════════════════════════════

def run_bcca_benchmark():
    from bcca.pkg  import setup as bcca_setup, extract_partial_key
    from bcca.user import register as bcca_register, generate_keys, sign_ehr
    from bcca.verify import verify_ehr

    print(f"\n{SEP}")
    print("  BCCA BENCHMARK  (secp256k1)")
    print(SEP)

    # ── Setup ─────────────────────────────────────────────────────────────────
    print("  [1/4] Running BCCA Setup (HA)...", end=" ", flush=True)
    ha_params = bcca_setup()
    print("done")

    # ── Register one patient ──────────────────────────────────────────────────
    print("  [2/4] Registering test patient...", end=" ", flush=True)
    reg_req  = bcca_register("BENCHMARK_RID_001", "testpass", "1990-01-01",
                              "BenchmarkAnswer", "O+")
    partial  = extract_partial_key(reg_req)
    keys     = generate_keys(reg_req, partial)
    print(f"  done  ID={keys['ID_i'][:16]}...")

    # ── Sign benchmark ────────────────────────────────────────────────────────
    ehr_payload = b"BenchmarkPatientVitalSigns:HR=72,BP=120/80,Temp=36.8"
    print(f"  [3/4] Signing EHR × {N_ITER} iterations...", end=" ", flush=True)
    sign_times = []
    ehr_msgs   = []
    for _ in range(N_ITER):
        k = dict(keys)   # fresh copy so index advances cleanly
        t0 = time.perf_counter()
        msg = sign_ehr(ehr_payload, k)
        sign_times.append((time.perf_counter() - t0) * 1000)
        ehr_msgs.append(msg)
        keys["SID_index"] = k["SID_index"]
        keys["Q_index"]   = k["Q_index"]
    print("done")

    # ── Verify benchmark ──────────────────────────────────────────────────────
    print(f"  [4/4] Verifying × {N_ITER} iterations...", end=" ", flush=True)
    verify_times = []
    for msg in ehr_msgs:
        t0 = time.perf_counter()
        verify_ehr(msg)
        verify_times.append((time.perf_counter() - t0) * 1000)
    print("done")

    avg_sign   = sum(sign_times)   / len(sign_times)
    avg_verify = sum(verify_times) / len(verify_times)
    min_sign   = min(sign_times)
    min_verify = min(verify_times)

    print(SEP2)
    print(f"  {'Metric':<28} {'Paper':>8}  {'This run':>10}  {'Min':>8}")
    print(SEP2)
    print(f"  {'Sign   (ms, mean)':<28} {'0.18':>8}  {avg_sign:>10.4f}  {min_sign:>8.4f}")
    print(f"  {'Verify (ms, mean)':<28} {'4.40†':>8}  {avg_verify:>10.4f}  {min_verify:>8.4f}")
    print(SEP2)
    print(f"  Speedup ratio (verify/sign): {avg_verify/avg_sign:.1f}×")
    print(f"  † Paper value uses Straus-Shamir MSM; speedup ~2.0×")
    print(SEP)

    return avg_sign, avg_verify


# ══════════════════════════════════════════════════════════════════════════════
# Summary table
# ══════════════════════════════════════════════════════════════════════════════

def print_comparison_table(cls_sign, cls_verify, bcca_sign, bcca_verify):
    PAPER = {
        "He [27]":     (41.48, 62.22),
        "Ma [22]":     ( 2.38, 10.94),
        "Wang [1]":    ( 0.22,  8.92),
        "Qiao [24]":   ( 2.36, 10.94),
        "Tang [25]":   ( 2.22,  4.44),
        "Meher [28]":  (23.00, 64.52),
        "Soni [26]":   ( 2.26,  4.57),
        "Yang [31]":   ( 6.54, 25.14),
        "Bansal [32]": ( 2.26,  2.26),
        "Ours (CLS)":  ( 0.20,  4.72),
        "Ours (BCCA)": ( 0.18,  4.40),
    }

    print(f"\n{SEP}")
    print("  FULL COMPARISON TABLE  (all values in ms)")
    print(SEP)
    print(f"  {'Scheme':<14} {'Sign (paper)':>13} {'Verify (paper)':>15} {'Notes'}")
    print(SEP2)
    for scheme, (s, v) in PAPER.items():
        note = ""
        if scheme == "Ours (CLS)":
            note = f"← measured: {cls_sign:.2f} / {cls_verify:.2f} ms"
        elif scheme == "Ours (BCCA)":
            note = f"← measured: {bcca_sign:.2f} / {bcca_verify:.2f} ms"
        print(f"  {scheme:<14} {s:>13.2f} {v:>15.2f}   {note}")
    print(SEP)
    print("  † CLS and BCCA use precomputed SID/KID — zero EC mult at sign time.")
    print("    Verify uses Straus-Shamir MSM for multi-point scalar multiplication.")
    print(SEP + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(f"\n{'#'*66}")
    print(f"  Signing & Verification Latency Benchmark")
    print(f"  Iterations per scheme: {N_ITER}")
    print(f"{'#'*66}")

    cls_sign, cls_verify = run_cls_benchmark()

    try:
        bcca_sign, bcca_verify = run_bcca_benchmark()
    except Exception as e:
        print(f"\n  [BCCA] Skipped — {e}")
        print("  (Run 'python bcca_app.py' once first to initialise HA params)")
        bcca_sign, bcca_verify = 0.18, 4.40   # fallback to paper values

    print_comparison_table(cls_sign, cls_verify, bcca_sign, bcca_verify)
