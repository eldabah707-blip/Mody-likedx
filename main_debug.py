from flask import Flask, request, jsonify
import os
import concurrent.futures
import requests

app = Flask(__name__)

JWT_API_BASE = "https://mody-panel-jwt.vercel.app/token"

SERVER_ACCOUNT_FILES = {
    "BD": "account_bd.txt",
    "IND": "account_ind.txt",
    "BR": "account_br.txt",
    "US": "account_us.txt",
    "SAC": "account_sac.txt",
    "NA": "account_na.txt",
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
JWT_WORKERS = 20


def load_accounts(server_name):
    filename = SERVER_ACCOUNT_FILES.get(server_name.upper())
    if not filename:
        return []

    path = os.path.join(BASE_DIR, filename)
    if not os.path.exists(path):
        return []

    accounts = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            uid, password = line.split(":", 1)
            if uid.strip() and password.strip():
                accounts.append((uid.strip(), password.strip()))
    return accounts


def check_jwt(uid, password):
    try:
        r = requests.get(
            JWT_API_BASE,
            params={"uid": uid, "password": password},
            timeout=15,
        )

        result = {
            "uid": uid,
            "http_status": r.status_code,
            "token_received": False,
            "error": None,
        }

        if r.status_code != 200:
            result["error"] = f"JWT API returned HTTP {r.status_code}"
            return result

        try:
            data = r.json()
        except ValueError:
            result["error"] = "JWT API did not return valid JSON"
            return result

        token = None
        if isinstance(data, dict):
            token = data.get("token") or data.get("jwt") or data.get("access_token")
            if not token and isinstance(data.get("data"), dict):
                token = (
                    data["data"].get("token")
                    or data["data"].get("jwt")
                    or data["data"].get("access_token")
                )
        elif isinstance(data, str):
            token = data.strip()

        result["token_received"] = bool(token)

        if not token:
            result["error"] = "HTTP 200 but no token field was found"

        return result

    except requests.RequestException as e:
        return {
            "uid": uid,
            "http_status": 0,
            "token_received": False,
            "error": f"{type(e).__name__}: {e}",
        }


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "NIROBxFREExLIKE-DIAGNOSTIC",
        "jwt_api": JWT_API_BASE,
        "servers": list(SERVER_ACCOUNT_FILES.keys()),
    })


@app.get("/debug-jwt")
def debug_jwt():
    server = request.args.get("server_name", "").upper()

    if server not in SERVER_ACCOUNT_FILES:
        return jsonify({
            "error": "Invalid server_name",
            "allowed": list(SERVER_ACCOUNT_FILES.keys()),
        }), 400

    accounts = load_accounts(server)

    if not accounts:
        return jsonify({
            "server": server,
            "accounts_loaded": 0,
            "jwt_success": 0,
            "jwt_failed": 0,
            "error": "No valid uid:password accounts found",
        }), 500

    results = []
    workers = min(JWT_WORKERS, len(accounts))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(check_jwt, uid, password)
            for uid, password in accounts
        ]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: x["uid"])

    success = sum(1 for x in results if x["token_received"])

    return jsonify({
        "server": server,
        "jwt_api": JWT_API_BASE,
        "accounts_loaded": len(accounts),
        "jwt_success": success,
        "jwt_failed": len(results) - success,
        "results": results,
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
        use_reloader=False,
    )
