from flask import Blueprint, request, jsonify
from src.hybrid_waf.utils.signature_checker import check_signature
import logging
import os

BLOCK_FILE = "logs/blocked_ips.txt"
BLOCK_LIMIT = 5
blocked_ips_count = {}

# ---------------- LOGGER ---------------- #
waf_logger = logging.getLogger('waf_detections')
waf_logger.setLevel(logging.INFO)
if not os.path.exists("logs"):
    os.makedirs("logs")
fh = logging.FileHandler('logs/detections.log')
formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
fh.setFormatter(formatter)
if not waf_logger.handlers:
    waf_logger.addHandler(fh)

# ---------------- UTIL ---------------- #
def load_blocked_ips():
    if os.path.exists(BLOCK_FILE):
        with open(BLOCK_FILE, "r") as f:
            return set(line.strip() for line in f.readlines())
    return set()

def save_blocked_ip(ip):
    with open(BLOCK_FILE, "a") as f:
        f.write(ip + "\n")

def get_severity(user_input, attack_type):
    user_input_upper = user_input.upper()
    if "DROP" in user_input_upper or "UNION" in user_input_upper:
        return "HIGH"
    if attack_type == "ML":
        return "MEDIUM"
    if "SELECT" in user_input_upper or "OR 1=1" in user_input_upper:
        return "MEDIUM"
    return "LOW"

# ---------------- ROUTE ---------------- #
proxy_bp = Blueprint('proxy', __name__)

@proxy_bp.route('/check_request', methods=['POST'])
def check_request():
    data = request.get_json()
    user_input = data.get("user_request", "")
    uri = data.get("uri", user_input)
    get_data = data.get("get_data", "")
    post_data = data.get("post_data", "")
    ip = request.remote_addr

    if ip in load_blocked_ips():
        return jsonify({"status": "blocked",
                        "message": "🚫 Your IP has been permanently blocked."})

    signature_result = check_signature(user_input)

    # VALID
    if signature_result == "valid":
        waf_logger.info(f"IP={ip} | INPUT={user_input} | STATUS=valid")
        return jsonify({"status": "valid", "message": "Request is safe."})

    # SIGNATURE ATTACK
    if signature_result == "malicious":
        blocked_ips_count[ip] = blocked_ips_count.get(ip, 0) + 1
        severity = get_severity(user_input, "signature")
        waf_logger.info(
            f"IP={ip} | INPUT={user_input} | STATUS=malicious | TYPE=signature | SEVERITY={severity}"
        )
        if blocked_ips_count[ip] >= BLOCK_LIMIT:
            save_blocked_ip(ip)
        return jsonify({"status": "malicious",
                        "severity": severity,
                        "message": "Signature attack blocked."})

    # ML DETECTION
    if signature_result == "obfuscated":
        from src.hybrid_waf.utils.preprocessor import extract_features
        from src.hybrid_waf.utils.ml_checker import check_ml_prediction
        features = extract_features(uri, get_data, post_data)
        prediction = check_ml_prediction(features)

        if prediction == 1:
            blocked_ips_count[ip] = blocked_ips_count.get(ip, 0) + 1
            severity = get_severity(user_input, "ML")
            waf_logger.info(
                f"IP={ip} | INPUT={user_input} | STATUS=malicious | TYPE=ML | SEVERITY={severity}"
            )
            if blocked_ips_count[ip] >= BLOCK_LIMIT:
                save_blocked_ip(ip)
            return jsonify({"status": "malicious",
                            "severity": severity,
                            "message": "ML attack blocked."})
        else:
            waf_logger.info(
                f"IP={ip} | INPUT={user_input} | STATUS=valid"
            )
            return jsonify({"status": "valid",
                            "message": "ML scan passed."})