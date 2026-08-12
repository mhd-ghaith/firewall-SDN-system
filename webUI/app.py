import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

from flask import Flask, request, jsonify, render_template
import requests

app = Flask(__name__,
            template_folder=os.path.join(BASE_DIR, 'templates'),
            static_folder=os.path.join(BASE_DIR, 'static'))

RYU_REST_URL = "http://127.0.0.1:8080"

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/policies")
def policies():
    return render_template("policies.html")

@app.route("/monitoring")
def monitoring():
    return render_template("monitoring.html")

@app.route("/logs")
def logs():
    return render_template("logs.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/api/rules", methods=["GET"])
def get_rules():
    try:
        resp = requests.get(f"{RYU_REST_URL}/firewall/rules")
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/rules/add", methods=["POST"])
def add_rule():
    rule = request.get_json()
    try:
        requests.post(f"{RYU_REST_URL}/firewall/rules/add", json=rule)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/rules/modify", methods=["POST"])
def modify_rule():
    rule = request.get_json()
    try:
        requests.post(f"{RYU_REST_URL}/firewall/rules/modify", json=rule)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/rules/delete", methods=["POST"])
def delete_rule():
    rule = request.get_json()
    try:
        requests.post(f"{RYU_REST_URL}/firewall/rules/delete", json=rule)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/logs", methods=["GET"])
def get_logs():
    try:
        resp = requests.get(f"{RYU_REST_URL}/firewall/logs")
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/logs/clear", methods=["POST"])
def clear_logs():
    try:
        requests.post(f"{RYU_REST_URL}/firewall/logs/clear")
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/logs/add", methods=["POST"])
def add_log():
    log = request.get_json()
    try:
        requests.post(f"{RYU_REST_URL}/firewall/logs/add", json=log)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/health", methods=["GET"])
def health():
    try:
        r = requests.get(f"{RYU_REST_URL}/firewall/rules", timeout=2)
        if r.status_code == 200:
            return jsonify({"status": "online"})
        return jsonify({"status": "offline"}), 503
    except Exception:
        return jsonify({"status": "offline"}), 503

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
