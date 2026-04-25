"""
Healthcare BCCA Flask Application
===================================
Blockchain-Based Certificateless Conditional Anonymous Authentication
for Healthcare EHR Sharing.

Implements all 10 algorithms from healthcare_ehr_scheme.md as REST
endpoints, plus a full HTML UI for patients, doctors, and the Hospital
Admin (HA).

Roles
-----
  Hospital Admin (HA)  → /ha/...
  Patient              → /patient/...
  Doctor               → /doctor/...
  Blockchain Node      → /node/...  (consensus server endpoints)
"""

import os, json, time, io, hashlib, base64
from typing import Dict, List, Optional
from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, send_file)
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from web3 import Web3, HTTPProvider

# ---------- BCCA modules ----------
from bcca.pkg        import setup as ha_setup, extract_partial_key
from bcca.user       import (register as bcca_register, generate_keys,
                              login as bcca_login, sign_ehr, decrypt_ehr,
                              PRECOMPUTE_N)
from bcca.verify     import verify_ehr, batch_verify_ehr
from bcca.mutual_auth import (patient_auth_request, doctor_verify_and_respond,
                               patient_verify_and_key, doctor_compute_session_key)
from bcca.revocation import revoke_user_access, modify_evidence
from bcca.params_store import (load_params, get_user, get_all_users,
                                get_evidence_entries, is_revoked)
from bcca.ecc_utils  import ECPoint

# ──────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.urandom(32)          # session encryption key

UPLOAD_FOLDER   = os.path.join("static", "ehr_files")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Keys stored in-memory per session (in production: secure device storage)
# key: session_id → full_key dict
_KEY_STORE: Dict[str, dict] = {}

# In-memory EHR message store (mirrors what is submitted to blockchain)
_EHR_MSGS: List[dict] = []

# ──────────────────────────────────────────────────────────────────────────────
# Blockchain helpers
# ──────────────────────────────────────────────────────────────────────────────

BLOCKCHAIN_ADDR   = "http://127.0.0.1:8545"
BCCA_CONTRACT_ABI = "BCCA.json"          # compiled ABI (truffle build output)
BCCA_CONTRACT_ADDR = None                # set after deployment

_w3      = None
_contract = None

def _get_web3():
    global _w3
    if _w3 is None:
        _w3 = Web3(HTTPProvider(BLOCKCHAIN_ADDR))
        _w3.eth.default_account = _w3.eth.accounts[0]
    return _w3

def _get_contract():
    global _contract, BCCA_CONTRACT_ADDR
    if _contract is not None:
        return _contract
    addr_file = os.path.join("bcca_data", "contract_address.txt")
    if not os.path.exists(addr_file):
        return None
    with open(addr_file) as f:
        BCCA_CONTRACT_ADDR = f.read().strip()
    abi_path = os.path.join("build", "contracts", "BCCA_Healthcare.json")
    if not os.path.exists(abi_path):
        return None
    with open(abi_path) as f:
        compiled = json.load(f)
    w3 = _get_web3()
    _contract = w3.eth.contract(address=BCCA_CONTRACT_ADDR,
                                 abi=compiled["abi"])
    return _contract

def _blockchain_register(pseudo_id, gpk, upk, E_i, h1_i, role_int):
    """Call registerUser on BCCA smart contract."""
    try:
        c = _get_contract()
        if c is None:
            return
        tx = c.functions.registerUser(pseudo_id, gpk, upk, E_i, h1_i, role_int).transact()
        _get_web3().eth.wait_for_transaction_receipt(tx)
    except Exception as e:
        app.logger.warning(f"Blockchain registration skipped: {e}")

def _blockchain_store_ehr(msg: dict) -> str:
    """Call storeEHRRecord on BCCA smart contract. Returns blockHash hex."""
    try:
        c = _get_contract()
        if c is None:
            return ""
        tx = c.functions.storeEHRRecord(
            msg["ID_i"], msg["sigma_i"], msg["KID_k"],
            msg["c_i"], msg["Q_k"], int(msg["T_i"])
        ).transact()
        receipt = _get_web3().eth.wait_for_transaction_receipt(tx)
        # Parse EHRUploaded event to get blockHash
        logs = c.events.EHRUploaded().process_receipt(receipt)
        if logs:
            return logs[0]["args"]["blockHash"].hex()
    except Exception as e:
        app.logger.warning(f"Blockchain EHR store skipped: {e}")
    return ""

# ──────────────────────────────────────────────────────────────────────────────
# Utility
# ──────────────────────────────────────────────────────────────────────────────

def _session_keys() -> Optional[dict]:
    sid = session.get("user_id")
    return _KEY_STORE.get(sid)

def _save_session_keys(keys: dict):
    sid = session.get("user_id")
    if sid:
        _KEY_STORE[sid] = keys

def _require_role(*roles):
    """Return user keys if logged in with correct role, else None."""
    keys = _session_keys()
    if keys is None:
        return None
    if keys.get("role") not in roles:
        return None
    return keys

# ──────────────────────────────────────────────────────────────────────────────
# Home
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    params_ready = load_params() is not None
    return render_template("bcca_index.html", params_ready=params_ready)

# ──────────────────────────────────────────────────────────────────────────────
# HOSPITAL ADMIN (HA) — Algorithm 1 & 3
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/ha/login", methods=["GET", "POST"])
def ha_login():
    if request.method == "POST":
        if (request.form.get("username") == "admin" and
                request.form.get("password") == "admin"):
            session["user_id"] = "ha_admin"
            session["role"]    = "HA"
            return redirect(url_for("ha_dashboard"))
        return render_template("bcca_ha_login.html",
                               error="Invalid credentials")
    return render_template("bcca_ha_login.html")

@app.route("/ha/dashboard")
def ha_dashboard():
    if session.get("role") != "HA":
        return redirect(url_for("ha_login"))
    params  = load_params()
    users   = get_all_users()
    evid    = get_evidence_entries()
    ehrs    = _EHR_MSGS
    return render_template("bcca_ha_dashboard.html",
                           params=params, users=users,
                           evidence=evid, ehr_count=len(ehrs))

@app.route("/ha/setup", methods=["POST"])
def ha_setup_action():
    if session.get("role") != "HA":
        return redirect(url_for("ha_login"))
    try:
        params = ha_setup()
        return render_template("bcca_ha_dashboard.html",
                               params=params, users=get_all_users(),
                               evidence=get_evidence_entries(),
                               ehr_count=len(_EHR_MSGS),
                               msg="System parameters generated successfully.")
    except Exception as e:
        return render_template("bcca_ha_dashboard.html",
                               params=None, users={},
                               evidence=[], ehr_count=0,
                               error=str(e))

@app.route("/ha/extract_key", methods=["GET", "POST"])
def ha_extract_key():
    """HA processes a pending registration request and issues partial key."""
    if session.get("role") != "HA":
        return redirect(url_for("ha_login"))
    if request.method == "POST":
        try:
            reg = {
                "upk"  : request.form["upk"],
                "RID"  : request.form["rid"],
                "UPW"  : request.form["upw"],
                "alpha": request.form["alpha"],
                "role" : request.form["role"].upper(),
            }
            partial = extract_partial_key(reg)
            # Register on blockchain
            role_int = 0 if reg["role"] == "PATIENT" else 1
            _blockchain_register(partial["ID_i"], partial["gpk_i"],
                                  reg["upk"], partial["E_i"],
                                  partial["h1_i"], role_int)
            return render_template("bcca_ha_keygen_result.html",
                                   partial=partial)
        except Exception as e:
            return render_template("bcca_ha_extract.html", error=str(e))
    return render_template("bcca_ha_extract.html")

@app.route("/ha/revoke", methods=["GET", "POST"])
def ha_revoke():
    if session.get("role") != "HA":
        return redirect(url_for("ha_login"))
    if request.method == "POST":
        try:
            pseudo_id = request.form["pseudo_id"]
            evidence  = request.form["evidence"]
            # Fetch E_i from local user store
            user_rec  = get_user(pseudo_id)
            if not user_rec:
                raise ValueError("User not found in registry.")
            entry = revoke_user_access(pseudo_id, evidence, user_rec["E_i"])
            # Push to smart contract
            try:
                c = _get_contract()
                if c:
                    tx = c.functions.addEvidenceEntry(
                        pseudo_id, entry["HK_i"], entry["CH_i"],
                        entry["j_i"], entry["cred_i"]
                    ).transact()
                    _get_web3().eth.wait_for_transaction_receipt(tx)
            except Exception as be:
                app.logger.warning(f"Blockchain revoke skipped: {be}")
            return render_template("bcca_ha_dashboard.html",
                                   params=load_params(), users=get_all_users(),
                                   evidence=get_evidence_entries(),
                                   ehr_count=len(_EHR_MSGS),
                                   msg=f"User {pseudo_id[:20]}... revoked.")
        except Exception as e:
            return render_template("bcca_ha_dashboard.html",
                                   params=load_params(), users=get_all_users(),
                                   evidence=get_evidence_entries(),
                                   ehr_count=len(_EHR_MSGS),
                                   error=str(e))
    return render_template("bcca_ha_dashboard.html",
                           params=load_params(), users=get_all_users(),
                           evidence=get_evidence_entries(),
                           ehr_count=len(_EHR_MSGS))

@app.route("/ha/modify_evidence", methods=["POST"])
def ha_modify_evidence():
    if session.get("role") != "HA":
        return redirect(url_for("ha_login"))
    try:
        pseudo_id    = request.form["pseudo_id"]
        new_evidence = request.form["new_evidence"]
        updated = modify_evidence(pseudo_id, new_evidence)
        # Update on blockchain
        try:
            c = _get_contract()
            if c:
                tx = c.functions.modifyEvidenceEntry(
                    pseudo_id, updated["cred_i"], updated["CH_i"]
                ).transact()
                _get_web3().eth.wait_for_transaction_receipt(tx)
        except Exception as be:
            app.logger.warning(f"Blockchain modify skipped: {be}")
        msg = f"Evidence for {pseudo_id[:20]}... updated. Block hash UNCHANGED."
        return render_template("bcca_ha_dashboard.html",
                               params=load_params(), users=get_all_users(),
                               evidence=get_evidence_entries(),
                               ehr_count=len(_EHR_MSGS), msg=msg)
    except Exception as e:
        return render_template("bcca_ha_dashboard.html",
                               params=load_params(), users=get_all_users(),
                               evidence=get_evidence_entries(),
                               ehr_count=len(_EHR_MSGS), error=str(e))

# ──────────────────────────────────────────────────────────────────────────────
# REGISTRATION — Algorithm 2 (Patient or Doctor)
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            role   = request.form["role"].upper()
            rid    = request.form["rid"]
            pw     = request.form["password"]
            dob    = request.form["dob"]
            sa     = request.form["security_answer"]
            od     = request.form["other_details"]

            reg_pkt, local = bcca_register(rid, pw, dob, sa, od, role)
            # Store local key material temporarily in session for key-gen step
            session["pending_local"]  = local
            session["pending_reg"]    = reg_pkt
            return render_template("bcca_register_result.html",
                                   reg=reg_pkt, local=local)
        except Exception as e:
            return render_template("bcca_register.html", error=str(e))
    return render_template("bcca_register.html")

# ──────────────────────────────────────────────────────────────────────────────
# KEY GENERATION — Algorithm 4
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/keygen", methods=["GET", "POST"])
def keygen():
    if request.method == "POST":
        try:
            # Partial key material typed/pasted from HA response
            partial = {
                "ID_i"  : request.form["id_i"],
                "gpk_i" : request.form["gpk_i"],
                "psk_i" : request.form["psk_i"],
                "E_i"   : request.form["e_i"],
                "d_i"   : request.form.get("d_i", "0"),
                "A_i"   : request.form["a_i"],
                "B_i"   : request.form["b_i"],
                "h1_i"  : request.form["h1_i"],
                "role"  : request.form["role"].upper(),
            }
            if request.form.get("y"):
                partial["y"] = request.form["y"]

            local = session.get("pending_local")
            if not local:
                raise ValueError("No pending registration. Please register first.")

            full_key = generate_keys(partial, local)

            # Save to key store (keyed by pseudonym ID)
            _KEY_STORE[partial["ID_i"]] = full_key
            session["user_id"] = partial["ID_i"]
            session["role"]    = partial["role"]

            return render_template("bcca_keygen_result.html",
                                   keys=full_key, role=partial["role"])
        except Exception as e:
            return render_template("bcca_keygen.html", error=str(e))
    return render_template("bcca_keygen.html")

# ──────────────────────────────────────────────────────────────────────────────
# LOGIN — Algorithm 5 (Multi-Factor)
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            pseudo_id = request.form["pseudo_id"]
            rid       = request.form["rid"]
            password  = request.form["password"]
            dob       = request.form["dob"]
            sa        = request.form["security_answer"]
            od        = request.form["other_details"]

            stored = _KEY_STORE.get(pseudo_id)
            if stored is None:
                raise ValueError("No keys found for this pseudonym ID. "
                                 "Complete key generation first.")

            ok = bcca_login(stored, rid, password, dob, sa, od)
            if ok:
                session["user_id"] = pseudo_id
                session["role"]    = stored["role"]
                if stored["role"] == "PATIENT":
                    return redirect(url_for("patient_dashboard"))
                else:
                    return redirect(url_for("doctor_dashboard"))
            else:
                return render_template("bcca_login.html",
                                       error="Login failed. Check your credentials.")
        except Exception as e:
            return render_template("bcca_login.html", error=str(e))
    return render_template("bcca_login.html")

@app.route("/logout")
def logout():
    uid = session.get("user_id")
    if uid and uid != "ha_admin":
        _KEY_STORE.pop(uid, None)
    session.clear()
    return redirect(url_for("home"))

# ──────────────────────────────────────────────────────────────────────────────
# PATIENT DASHBOARD & EHR UPLOAD — Algorithm 6
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/patient/dashboard")
def patient_dashboard():
    keys = _require_role("PATIENT")
    if keys is None:
        return redirect(url_for("login"))
    # Collect this patient's EHR records
    pid  = session["user_id"]
    ehrs = [m for m in _EHR_MSGS if m.get("ID_i") == pid]
    return render_template("bcca_patient_dashboard.html",
                           keys=keys, ehrs=ehrs)

@app.route("/patient/upload_ehr", methods=["GET", "POST"])
def upload_ehr():
    keys = _require_role("PATIENT")
    if keys is None:
        return redirect(url_for("login"))
    if request.method == "POST":
        try:
            # Collect EHR data from form fields (vital signs, notes, etc.)
            vitals  = request.form.get("vitals", "")
            notes   = request.form.get("notes", "")
            report_file = request.files.get("report_file")

            ehr_payload = {
                "vitals"   : vitals,
                "notes"    : notes,
                "patient"  : session["user_id"],
                "timestamp": int(time.time()),
            }
            if report_file and report_file.filename:
                fname     = secure_filename(report_file.filename)
                file_bytes = report_file.read()
                ehr_payload["file_name"] = fname
                ehr_payload["file_data"] = base64.b64encode(file_bytes).decode()

            ehr_bytes = json.dumps(ehr_payload).encode("utf-8")

            # Algorithm 6: Sign & Encrypt
            ehr_msg = sign_ehr(ehr_bytes, keys)
            _save_session_keys(keys)          # save updated SID index

            # Algorithm 7: Verify before storing on chain
            valid, reason = verify_ehr(ehr_msg)
            if not valid:
                return render_template("bcca_upload_ehr.html",
                                       error=f"Signature verification failed: {reason}")

            # Store on blockchain
            block_hash = _blockchain_store_ehr(ehr_msg)
            ehr_msg["block_hash"]   = block_hash
            ehr_msg["verified"]     = True
            ehr_msg["ehr_preview"]  = vitals[:60] + ("..." if len(vitals) > 60 else "")
            _EHR_MSGS.append(ehr_msg)

            return render_template("bcca_upload_ehr.html",
                                   success=True, ehr_msg=ehr_msg,
                                   block_hash=block_hash)
        except Exception as e:
            return render_template("bcca_upload_ehr.html", error=str(e))
    return render_template("bcca_upload_ehr.html")

# ──────────────────────────────────────────────────────────────────────────────
# DOCTOR DASHBOARD, EHR ACCESS & DECRYPTION — Algorithm 7 Part B
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/doctor/dashboard")
def doctor_dashboard():
    keys = _require_role("DOCTOR")
    if keys is None:
        return redirect(url_for("login"))
    # All EHR records visible to the doctor
    return render_template("bcca_doctor_dashboard.html",
                           keys=keys, ehrs=_EHR_MSGS)

@app.route("/doctor/decrypt_ehr", methods=["POST"])
def doctor_decrypt_ehr():
    keys = _require_role("DOCTOR")
    if keys is None:
        return redirect(url_for("login"))
    try:
        c_i_hex = request.form["c_i"]
        Q_k_hex = request.form["Q_k"]
        plaintext_bytes = decrypt_ehr(c_i_hex, Q_k_hex, keys)
        plaintext = plaintext_bytes.decode("utf-8")
        ehr_data  = json.loads(plaintext)

        # Log access on blockchain
        try:
            c = _get_contract()
            if c:
                block_hash_hex = request.form.get("block_hash", "0" * 64)
                patient_pid    = request.form.get("patient_pid", "")
                tx = c.functions.logEHRAccess(
                    session["user_id"], patient_pid, block_hash_hex
                ).transact()
                _get_web3().eth.wait_for_transaction_receipt(tx)
        except Exception as be:
            app.logger.warning(f"Blockchain access log skipped: {be}")

        return render_template("bcca_ehr_view.html",
                               ehr=ehr_data, decrypted=True)
    except Exception as e:
        return render_template("bcca_doctor_dashboard.html",
                               keys=keys, ehrs=_EHR_MSGS,
                               error=str(e))

# ──────────────────────────────────────────────────────────────────────────────
# MUTUAL AUTHENTICATION — Algorithm 8
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/auth/patient_request", methods=["GET", "POST"])
def patient_auth_req():
    keys = _require_role("PATIENT")
    if keys is None:
        return redirect(url_for("login"))
    if request.method == "POST":
        try:
            doctor_pseudo = request.form["doctor_pseudo_id"]
            doc_pub       = get_user(doctor_pseudo)
            if not doc_pub:
                raise ValueError("Doctor not found in registry.")
            if doc_pub.get("role") != "DOCTOR":
                raise ValueError("Target is not a DOCTOR.")

            auth_req, ephemeral = patient_auth_request(keys, doc_pub)
            _save_session_keys(keys)

            # Store ephemeral in session for session key step
            session["ephemeral_a"]    = ephemeral
            session["target_doctor"]  = doctor_pseudo
            # In a real system, C_a would be sent to cloud server → doctor
            # Here we store it for demonstration
            session["pending_auth_req"] = auth_req

            return render_template("bcca_mutual_auth.html",
                                   step="sent", auth_req=auth_req,
                                   doctor_id=doctor_pseudo[:20])
        except Exception as e:
            return render_template("bcca_mutual_auth.html",
                                   step="request", error=str(e))
    return render_template("bcca_mutual_auth.html", step="request",
                           users=get_all_users())

@app.route("/auth/doctor_verify", methods=["POST"])
def doctor_auth_verify():
    keys = _require_role("DOCTOR")
    if keys is None:
        return redirect(url_for("login"))
    try:
        auth_req_json = request.form["auth_request"]
        auth_req = json.loads(auth_req_json)

        patient_pub = get_user(auth_req["ID_a"])
        if not patient_pub:
            raise ValueError("Patient not found in registry.")

        auth_resp, ephemeral_b = doctor_verify_and_respond(auth_req, keys, patient_pub)
        _save_session_keys(keys)

        # Compute session key (doctor side)
        # Ephemeral Z_a from auth_req
        import json as _json
        ephemeral_b["Z_a"]  = auth_req["Z_a"]
        ephemeral_b["ID_a"] = auth_req["ID_a"]
        ephemeral_b["ID_b"] = keys["ID_i"]

        K_ab = doctor_compute_session_key(ephemeral_b, auth_req)
        session["session_key_b64"] = base64.b64encode(K_ab).decode()

        return render_template("bcca_mutual_auth_doctor.html",
                               auth_resp=auth_resp,
                               session_key=base64.b64encode(K_ab).decode()[:16] + "...")
    except Exception as e:
        return render_template("bcca_doctor_dashboard.html",
                               keys=keys, ehrs=_EHR_MSGS, error=str(e))

@app.route("/auth/patient_finalize", methods=["POST"])
def patient_auth_finalize():
    keys = _require_role("PATIENT")
    if keys is None:
        return redirect(url_for("login"))
    try:
        auth_resp_json = request.form["auth_response"]
        auth_resp  = json.loads(auth_resp_json)
        ephemeral_a = session.get("ephemeral_a")
        if not ephemeral_a:
            raise ValueError("No pending authentication request.")

        doctor_pub = get_user(auth_resp["ID_b"])
        K_ab = patient_verify_and_key(auth_resp, keys, doctor_pub, ephemeral_a)
        session["session_key_b64"] = base64.b64encode(K_ab).decode()
        session.pop("ephemeral_a", None)
        session.pop("pending_auth_req", None)

        return render_template("bcca_mutual_auth.html",
                               step="complete",
                               session_key=base64.b64encode(K_ab).decode()[:16] + "...",
                               doctor_id=auth_resp["ID_b"][:20])
    except Exception as e:
        return render_template("bcca_mutual_auth.html",
                               step="finalize", error=str(e))

# ──────────────────────────────────────────────────────────────────────────────
# BATCH VERIFICATION API — Algorithm 7 Part C
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/node/batch_verify", methods=["POST"])
def api_batch_verify():
    """Blockchain node batch-verifies all pending EHR messages."""
    data = request.get_json()
    msgs = data.get("messages", _EHR_MSGS)
    if not msgs:
        return jsonify({"valid": False, "reason": "No messages to verify."})
    valid, reason = batch_verify_ehr(msgs)
    return jsonify({"valid": valid, "reason": reason, "count": len(msgs)})

@app.route("/node/verify_one", methods=["POST"])
def api_verify_one():
    """Blockchain node verifies a single EHR message."""
    msg = request.get_json()
    valid, reason = verify_ehr(msg)
    return jsonify({"valid": valid, "reason": reason})

# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC REGISTRY VIEW
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/registry")
def registry():
    users = get_all_users()
    return render_template("bcca_registry.html", users=users)

@app.route("/audit_log")
def audit_log():
    """View blockchain audit log."""
    logs = []
    try:
        c = _get_contract()
        if c:
            count = c.functions.getAuditLogLength().call()
            for i in range(min(count, 100)):   # last 100 entries
                entry = c.functions.getAuditEntry(i).call()
                logs.append({
                    "actor": entry[0], "action": entry[1],
                    "target": entry[2], "timestamp": entry[3]
                })
    except Exception as e:
        app.logger.warning(f"Could not fetch audit log: {e}")
    return render_template("bcca_audit_log.html", logs=logs)

# ──────────────────────────────────────────────────────────────────────────────
# EVIDENCE CHAIN VIEW
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/evidence_chain")
def evidence_chain():
    entries = get_evidence_entries()
    return render_template("bcca_evidence_chain.html", entries=entries)

# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5001)
