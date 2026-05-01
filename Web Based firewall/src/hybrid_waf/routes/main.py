from flask import Blueprint, render_template, request, redirect, url_for, session, send_file
import requests
import os
from collections import Counter
import smtplib
from email.mime.text import MIMEText

main_bp = Blueprint('main', __name__)

# =============================
# ADMIN LOGIN CONFIG
# =============================

ADMIN_EMAIL = "lord2k41@gmail.com"
ADMIN_PASSWORD = "admin123"

login_attempts = {}


# =============================
# EMAIL ALERT FUNCTION
# =============================

def send_alert_email(ip):

    msg = MIMEText(f"""
⚠ Webrix Security Alert

Someone attempted to login to your Webrix Admin Dashboard.

IP Address: {ip}

If this was not you please investigate immediately.
""")

    msg["Subject"] = "Webrix Security Alert"
    msg["From"] = ADMIN_EMAIL
    msg["To"] = ADMIN_EMAIL

    try:

        server = smtplib.SMTP_SSL("smtp.gmail.com",465)

        # Replace with your Gmail APP PASSWORD
        server.login(ADMIN_EMAIL,"fipp yedw cvvl smqm")

        server.send_message(msg)

        server.quit()

    except:
        print("Email alert failed")


# =============================
# HOME
# =============================

@main_bp.route('/')
def index():
    return render_template('index.html')


@main_bp.route('/home')
def home():
    return render_template('home.html')


# =============================
# SECURE ADMIN LOGIN
# =============================

@main_bp.route('/admin-login', methods=["GET","POST"])
def admin_login():

    ip = request.remote_addr

    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")

        login_attempts[ip] = login_attempts.get(ip,0) + 1

        if login_attempts[ip] > 5:
            return "Too many login attempts. Try again later."

        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:

            session["admin"] = True
            login_attempts[ip] = 0

            return redirect(url_for("main.admin"))

        else:

            send_alert_email(ip)

            if not os.path.exists("logs"):
                os.makedirs("logs")

            with open("logs/login_attempts.log","a") as f:
                f.write(f"{ip} failed login attempt\n")

            return render_template("admin_login.html", error="Invalid credentials")

    return render_template("admin_login.html")


# =============================
# LOGOUT
# =============================

@main_bp.route('/logout')
def logout():

    session.pop("admin", None)

    return redirect(url_for("main.admin_login"))


# =============================
# DASHBOARD
# =============================

@main_bp.route('/admin')
def admin():

    if "admin" not in session:
        return redirect(url_for("main.admin_login"))

    log_file = "logs/detections.log"

    total = 0
    blocked = 0
    signature = 0
    ml = 0

    logs = []
    ip_counter = Counter()
    blocked_ips = []
    attack_locations = []

    if os.path.exists(log_file):

        with open(log_file) as f:
            lines = f.readlines()

        total = len(lines)

        for line in lines:

            logs.append(line.strip())

            if "STATUS=malicious" in line:
                blocked += 1

            if "TYPE=signature" in line:
                signature += 1

            if "TYPE=ML" in line:
                ml += 1

            if "IP=" in line:

                ip = line.split("IP=")[1].split("|")[0].strip()

                ip_counter[ip] += 1

                try:

                    res = requests.get(
                        f"http://ip-api.com/json/{ip}",
                        timeout=2
                    ).json()

                    if res["status"] == "success":

                        attack_locations.append({
                            "lat": res["lat"],
                            "lon": res["lon"],
                            "country": res["country"]
                        })

                except:
                    pass


    if os.path.exists("logs/blocked_ips.txt"):

        with open("logs/blocked_ips.txt") as f:
            blocked_ips = [x.strip() for x in f.readlines()]


    top_attackers = ip_counter.most_common(5)


    return render_template(
        "admin.html",

        total=total,
        blocked=blocked,
        signature=signature,
        ml=ml,

        logs=logs[::-1],

        blocked_ips=blocked_ips,
        top_attackers=top_attackers,

        attack_locations=attack_locations
    )


# =============================
# MANUAL BLOCK
# =============================

@main_bp.route('/manual-block',methods=["POST"])
def manual_block():

    if not session.get("admin"):
        return redirect(url_for("main.admin_login"))

    ip = request.form.get("ip")

    blocked_ips = []

    if os.path.exists("logs/blocked_ips.txt"):

        with open("logs/blocked_ips.txt") as f:
            blocked_ips = [x.strip() for x in f.readlines()]

    if ip not in blocked_ips:

        with open("logs/blocked_ips.txt","a") as f:
            f.write(ip+"\n")

    return redirect(url_for("main.admin"))


# =============================
# UNBLOCK
# =============================

@main_bp.route('/unblock/<ip>')
def unblock_ip(ip):

    if not session.get("admin"):
        return redirect(url_for("main.admin_login"))

    if os.path.exists("logs/blocked_ips.txt"):

        with open("logs/blocked_ips.txt") as f:
            lines = f.readlines()

        with open("logs/blocked_ips.txt","w") as f:

            for line in lines:

                if line.strip() != ip:
                    f.write(line)

    return redirect(url_for("main.admin"))


# =============================
# EXPORT LOGS
# =============================

@main_bp.route('/export-logs')
def export_logs():

    if not session.get("admin"):
        return redirect(url_for("main.admin_login"))

    return send_file("logs/detections.log", as_attachment=True)


# =============================
# LIVE ATTACK STREAM
# =============================

@main_bp.route('/live-attacks')
def live_attacks():

    logs=[]

    if os.path.exists("logs/detections.log"):

        with open("logs/detections.log") as f:
            logs=f.readlines()[-10:]

    return {"logs":logs[::-1]}
