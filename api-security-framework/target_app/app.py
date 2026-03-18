"""
target_app/app.py
-----------------
Deliberately vulnerable Flask API for demonstrating the security scanner.
DO NOT deploy this in production.

Vulnerabilities intentionally included:
  - OWASP API1: Broken Object Level Authorization (BOLA)
  - OWASP API2: Broken Authentication (weak JWT, no expiry)
  - OWASP API3: Broken Object Property Level Authorization
  - OWASP API4: Unrestricted Resource Consumption (no rate limiting)
  - OWASP API5: Broken Function Level Authorization
  - OWASP API8: Security Misconfiguration (debug mode, verbose errors)
"""

from flask import Flask, request, jsonify
import jwt
import datetime

app = Flask(__name__)
app.config["DEBUG"] = True  # VULN: debug mode enabled

SECRET_KEY = "supersecret123"  # VULN: hardcoded weak secret

# Simulated user database
USERS = {
    1: {"id": 1, "name": "Alice", "email": "alice@bank.com", "role": "user",   "balance": 50000},
    2: {"id": 2, "name": "Bob",   "email": "bob@bank.com",   "role": "user",   "balance": 75000},
    3: {"id": 3, "name": "Admin", "email": "admin@bank.com", "role": "admin",  "balance": 0},
}

LOANS = {
    101: {"id": 101, "user_id": 1, "amount": 10000, "status": "active"},
    102: {"id": 102, "user_id": 2, "amount": 25000, "status": "active"},
}


def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except Exception:
        return None


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    """Returns a JWT. VULN: no expiry set."""
    data = request.get_json() or {}
    username = data.get("username", "")
    # VULN: no password validation
    token = jwt.encode(
        {"username": username, "user_id": 1},  # always user_id=1
        SECRET_KEY,
        algorithm="HS256",
    )
    return jsonify({"token": token})


# ── Users ─────────────────────────────────────────────────────────────────────

@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    """VULN API1: No authorization check — any user can fetch any user record."""
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)  # VULN API3: returns balance field regardless of caller


@app.route("/api/users/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    """VULN API1 + API3: No ownership check, accepts any field including role."""
    data = request.get_json() or {}
    if user_id not in USERS:
        return jsonify({"error": "User not found"}), 404
    USERS[user_id].update(data)  # VULN: mass assignment — role can be escalated
    return jsonify(USERS[user_id])


# ── Loans ─────────────────────────────────────────────────────────────────────

@app.route("/api/loans/<int:loan_id>", methods=["GET"])
def get_loan(loan_id):
    """VULN API1: No check that the requesting user owns this loan."""
    loan = LOANS.get(loan_id)
    if not loan:
        return jsonify({"error": "Loan not found"}), 404
    return jsonify(loan)


# ── Admin ─────────────────────────────────────────────────────────────────────

@app.route("/api/admin/users", methods=["GET"])
def list_all_users():
    """VULN API5: Admin endpoint with no role check."""
    return jsonify(list(USERS.values()))


@app.route("/api/admin/export", methods=["GET"])
def export_data():
    """VULN API5: Sensitive export with no auth at all."""
    return jsonify({"users": list(USERS.values()), "loans": list(LOANS.values())})


# ── Search ────────────────────────────────────────────────────────────────────

@app.route("/api/search", methods=["GET"])
def search():
    """VULN API4: No rate limiting. VULN: reflects input directly."""
    query = request.args.get("q", "")
    results = [u for u in USERS.values() if query.lower() in u["name"].lower()]
    return jsonify({"query": query, "results": results})  # VULN: reflects raw input


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
