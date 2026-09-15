from flask import Flask, jsonify, render_template, send_file, request
from collections import Counter
from pathlib import Path
from datetime import datetime
import ipaddress

app = Flask(__name__)

BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "login_logs.txt"
REPORT_FILE = BASE_DIR / "security_report.txt"

# Create log file if it does not exist
LOG_FILE.touch(exist_ok=True)


# -----------------------------
# ANALYZE LOGIN LOGS
# -----------------------------
def analyze_logs():

    failed_attempts = Counter()
    total_attempts = Counter()

    ip_times = {}
    ip_status = {}

    # Read log file
    with open(LOG_FILE, "r", encoding="utf-8") as file:

        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                time, ip, status = [
                    value.strip() for value in line.split(",")
                ]

                status = status.upper()

                # Accept only valid time, IP and status
                datetime.strptime(time, "%H:%M")
                ipaddress.ip_address(ip)

                if status not in ["FAILED", "SUCCESS"]:
                    continue

                total_attempts[ip] += 1

                ip_status.setdefault(ip, []).append((time, status))
                ip_times.setdefault(ip, []).append(time)

                if status == "FAILED":
                    failed_attempts[ip] += 1

            except (ValueError, TypeError):
                # Skip malformed log lines
                continue

    alerts = []

    # Analyze each IP
    for ip in total_attempts:

        total = total_attempts[ip]
        failed = failed_attempts[ip]

        failure_rate = (failed / total) * 100

        # Basic alert level
        if failed >= 3:
            level = "HIGH"
        elif failed == 2:
            level = "MEDIUM"
        elif failed == 1:
            level = "LOW"
        else:
            level = "NORMAL"

        attack_types = []

        # -------------------------
        # 1. BRUTE FORCE
        # -------------------------
        brute_force = failed >= 3
        successful_login = None

        if brute_force:
            for time, status in ip_status[ip]:
                if status == "SUCCESS":
                    successful_login = time
                    break

            attack_types.append("Brute Force Attack")

        # -------------------------
        # 2. RAPID LOGIN
        # 3 or more attempts within 2 minutes
        # -------------------------
        rapid_attack = False

        try:
            time_values = [
                datetime.strptime(time, "%H:%M")
                for time, status in ip_status[ip]
            ]

            for i, start in enumerate(time_values):
                count = 0

                for current in time_values[i:]:
                    difference = (
                        current - start
                    ).total_seconds() / 60

                    if 0 <= difference <= 2:
                        count += 1

                if count >= 3:
                    rapid_attack = True
                    break

        except ValueError:
            rapid_attack = False

        if rapid_attack:
            attack_types.append("Rapid Login Attack")

        # -------------------------
        # 3. OFF-HOURS LOGIN
        # Before 06:00 or from 23:00
        # -------------------------
        off_hours = False

        for time, status in ip_status[ip]:
            try:
                hour = int(time.split(":")[0])

                if hour < 6 or hour >= 23:
                    off_hours = True
                    break

            except (ValueError, IndexError):
                continue

        if off_hours:
            attack_types.append("Off-Hours Login")

        # -------------------------
        # 4. HIGH FAILURE RATE
        # -------------------------
        high_failure_rate = total >= 3 and failure_rate >= 75

        if high_failure_rate:
            attack_types.append("High Failure Rate")

        # -------------------------
        # 5. ACCOUNT COMPROMISE INDICATOR
        # 3+ failures followed by a success
        # -------------------------
        account_compromise = False
        failures_before_success = 0

        for time, status in ip_status[ip]:
            if status == "FAILED":
                failures_before_success += 1

            elif status == "SUCCESS" and failures_before_success >= 3:
                account_compromise = True
                break

        if account_compromise:
            attack_types.append("Account Compromise Indicator")

        # -------------------------
        # 6. SUSPICIOUS IP ACTIVITY
        # -------------------------
        suspicious_ip = failed >= 2

        if suspicious_ip:
            attack_types.append("Suspicious IP Activity")

        # -------------------------
        # 7. REPEATED ATTACK PATTERN
        # -------------------------
        repeated_pattern = failed >= 3

        if repeated_pattern:
            attack_types.append("Repeated Attack Pattern")

        # Add alert if any detection matched
        if attack_types:
            alerts.append({
                "ip": ip,
                "level": level,
                "failed_attempts": failed,
                "total_attempts": total,
                "failure_rate": round(failure_rate, 2),
                "first_attempt": ip_times[ip][0],
                "last_attempt": ip_times[ip][-1],
                "brute_force": brute_force,
                "successful_login": successful_login,
                "rapid_attack": rapid_attack,
                "off_hours": off_hours,
                "high_failure_rate": high_failure_rate,
                "account_compromise": account_compromise,
                "suspicious_ip": suspicious_ip,
                "repeated_pattern": repeated_pattern,
                "attack_types": attack_types
            })

    # -----------------------------
    # DASHBOARD STATISTICS
    # -----------------------------
    total_logs = sum(total_attempts.values())
    failed_total = sum(failed_attempts.values())

    high_alerts = sum(
        1 for alert in alerts
        if alert["level"] == "HIGH"
    )

    # -----------------------------
    # ATTACK SUMMARY
    # -----------------------------
    attack_summary = {
        "Brute Force": 0,
        "Rapid Login": 0,
        "Off-Hours Login": 0,
        "High Failure Rate": 0,
        "Account Compromise": 0,
        "Suspicious IP": 0
    }

    for alert in alerts:
        if alert["brute_force"]:
            attack_summary["Brute Force"] += 1

        if alert["rapid_attack"]:
            attack_summary["Rapid Login"] += 1

        if alert["off_hours"]:
            attack_summary["Off-Hours Login"] += 1

        if alert["high_failure_rate"]:
            attack_summary["High Failure Rate"] += 1

        if alert["account_compromise"]:
            attack_summary["Account Compromise"] += 1

        if alert["suspicious_ip"]:
            attack_summary["Suspicious IP"] += 1

    return {
        "total_logs": total_logs,
        "failed_logins": failed_total,
        "suspicious_ips": len(alerts),
        "high_alerts": high_alerts,
        "attack_summary": attack_summary,
        "alerts": alerts
    }


# -----------------------------
# GENERATE SECURITY REPORT
# -----------------------------
def generate_security_report(data):

    with open(REPORT_FILE, "w", encoding="utf-8") as file:

        file.write("LOGIN ATTACK DETECTION SECURITY REPORT\n")
        file.write("=" * 50 + "\n\n")

        file.write(f"Total Logs      : {data['total_logs']}\n")
        file.write(f"Failed Logins   : {data['failed_logins']}\n")
        file.write(f"Suspicious IPs  : {data['suspicious_ips']}\n")
        file.write(f"High Alerts     : {data['high_alerts']}\n\n")

        if not data["alerts"]:
            file.write("No security alerts detected.\n")
            return

        for alert in data["alerts"]:

            file.write(f"Alert Level     : {alert['level']}\n")
            file.write(f"Suspicious IP   : {alert['ip']}\n")
            file.write(f"Total Attempts  : {alert['total_attempts']}\n")
            file.write(f"Failed Attempts : {alert['failed_attempts']}\n")
            file.write(f"Failure Rate    : {alert['failure_rate']}%\n")
            file.write(f"First Attempt   : {alert['first_attempt']}\n")
            file.write(f"Last Attempt    : {alert['last_attempt']}\n")

            file.write(
                "Attack Types    : "
                + ", ".join(alert["attack_types"])
                + "\n"
            )

            if alert["brute_force"]:
                file.write("Detection       : POSSIBLE BRUTE-FORCE ATTACK\n")

            if alert["successful_login"]:
                file.write(
                    f"Successful Login: {alert['successful_login']}\n"
                )

            if alert["rapid_attack"]:
                file.write("Detection       : RAPID LOGIN ATTACK\n")

            if alert["off_hours"]:
                file.write("Detection       : OFF-HOURS LOGIN\n")

            if alert["high_failure_rate"]:
                file.write("Detection       : HIGH FAILURE RATE\n")

            if alert["account_compromise"]:
                file.write(
                    "Detection       : POSSIBLE ACCOUNT COMPROMISE "
                    "(indicator only; needs investigation)\n"
                )

            if alert["suspicious_ip"]:
                file.write("Detection       : SUSPICIOUS IP ACTIVITY\n")

            if alert["repeated_pattern"]:
                file.write("Detection       : REPEATED ATTACK PATTERN\n")

            file.write("\n")


# -----------------------------
# DASHBOARD
# -----------------------------
@app.route("/")
def dashboard():
    return render_template("Dashboard.html")


# -----------------------------
# API: GET DASHBOARD DATA
# -----------------------------
@app.route("/api/data")
def api_data():

    data = analyze_logs()
    generate_security_report(data)

    return jsonify(data)


# -----------------------------
# ADD TEST LOG
# -----------------------------
@app.route("/add-log", methods=["POST"])
def add_log():

    data = request.get_json(silent=True) or {}

    time = str(data.get("time", "")).strip()
    ip = str(data.get("ip", "")).strip()
    status = str(data.get("status", "")).strip().upper()

    # Validate time
    try:
        datetime.strptime(time, "%H:%M")
    except ValueError:
        return jsonify({
            "error": "Time format HH:MM-la enter pannu."
        }), 400

    # Validate IP address
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({
            "error": "Valid IP address enter pannu."
        }), 400

    # Validate status
    if status not in ["FAILED", "SUCCESS"]:
        return jsonify({
            "error": "Status FAILED or SUCCESS-a irukkanum."
        }), 400

    # Save the new log
    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(f"{time},{ip},{status}\n")

    return jsonify({
        "message": "Test log successfully added!",
        "log": {
            "time": time,
            "ip": ip,
            "status": status
        }
    }), 201


# -----------------------------
# DOWNLOAD SECURITY REPORT
# -----------------------------
@app.route("/download-report")
def download_report():

    data = analyze_logs()
    generate_security_report(data)

    return send_file(
        REPORT_FILE,
        as_attachment=True,
        download_name="Security_Report.txt"
    )


# -----------------------------
# START SERVER
# -----------------------------
if __name__ == "__main__":

    print("\n🔐 LOGIN ATTACK DETECTION TOOL")
    print("🌐 Dashboard: http://127.0.0.1:5000")
    print("Press CTRL+C to stop the server.\n")

    app.run(debug=True)