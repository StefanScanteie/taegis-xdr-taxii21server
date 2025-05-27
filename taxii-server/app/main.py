from flask import Flask, request, render_template, redirect, url_for, jsonify, make_response, flash
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from stix2 import Indicator
from datetime import datetime
import json
import os
import re
import pandas as pd
from io import BytesIO
import logging
from config import load_config, setup_admin_password, change_admin_password

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SERVER_NAME'] = 'carried-lonely-design-bent.trycloudflare.com'  # Set the server name for URL generation
app.config['PREFERRED_URL_SCHEME'] = 'https'  # Force HTTPS
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-key-please-change')  # Required for flash messages
auth = HTTPBasicAuth()

# Load users from config
users = load_config().get("users", {})

# If no users exist and ADMIN_PASSWORD is set, create admin user
if not users and os.environ.get("ADMIN_PASSWORD"):
    users = setup_admin_password(os.environ["ADMIN_PASSWORD"])

DATA_PATH = "data/collection.json"

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username

def classify_ioc(value):
    value = value.strip().replace("[.]", ".")

    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", value):
        return "ipv4-addr", f"[ipv4-addr:value = '{value}']"
    if re.match(r"^https?://", value):
        return "url", f"[url:value = '{value}']"
    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return "file-md5", f"[file:hashes.MD5 = '{value}']"
    if re.match(r"^[a-fA-F0-9]{40}$", value):
        return "file-sha1", f"[file:hashes.SHA-1 = '{value}']"
    if re.match(r"^[a-fA-F0-9]{64}$", value):
        return "file-sha256", f"[file:hashes.SHA-256 = '{value}']"
    return "domain-name", f"[domain-name:value = '{value}']"

@app.route("/", methods=["GET", "POST"])
@auth.login_required
def index():
    if request.method == "POST":
        if "file" in request.files and request.files["file"].filename.endswith(".xlsx"):
            file = request.files["file"]
            df = pd.read_excel(BytesIO(file.read()))
            indicators = []

            for _, row in df.iterrows():
                raw = str(row["value"]).strip().replace("[.]", ".")
                desc = str(row.get("Threat Desc", "Excel Upload"))
                try:
                    ts = pd.to_datetime(row["Published Date"]).isoformat() + "Z"
                except Exception:
                    ts = datetime.utcnow().isoformat() + "Z"

                ioc_type, pattern = classify_ioc(raw)
                indicators.append(Indicator(
                    name=f"IOC: {raw}",
                    description=desc,
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=ts
                ))

            current = {"objects": []}
            if os.path.exists(DATA_PATH):
                with open(DATA_PATH) as f:
                    current = json.load(f)

            current["objects"].extend(json.loads(i.serialize()) for i in indicators)

            with open(DATA_PATH, "w") as f:
                json.dump(current, f)

            return redirect(url_for("index"))

        ioc_value = request.form.get("ioc", "").strip()
        threat = request.form.get("threat", "Manual Entry")
        if ioc_value:
            ioc_type, pattern = classify_ioc(ioc_value)
            indicator = Indicator(
                name=f"IOC: {ioc_value}",
                description=threat,
                pattern=pattern,
                pattern_type="stix",
                valid_from=datetime.utcnow().isoformat() + "Z"
            )

            current = {"objects": []}
            if os.path.exists(DATA_PATH):
                with open(DATA_PATH) as f:
                    current = json.load(f)

            current["objects"].append(json.loads(indicator.serialize()))

            with open(DATA_PATH, "w") as f:
                json.dump(current, f)

        return redirect(url_for("index"))

    indicators = []
    if os.path.exists(DATA_PATH):
        with open(DATA_PATH) as f:
            indicators = json.load(f)["objects"]
    return render_template("index.html", indicators=indicators)

@app.route("/delete/<ioc_id>", methods=["POST"])
@auth.login_required
def delete_ioc(ioc_id):
    if os.path.exists(DATA_PATH):
        with open(DATA_PATH) as f:
            data = json.load(f)
        data["objects"] = [obj for obj in data["objects"] if obj.get("id") != ioc_id]
        with open(DATA_PATH, "w") as f:
            json.dump(data, f)
    return redirect(url_for("index"))

@app.route("/change-password", methods=["GET", "POST"])
@auth.login_required
def change_password():
    try:
        if request.method == "POST":
            current_password = request.form.get("current_password")
            new_password = request.form.get("new_password")
            confirm_password = request.form.get("confirm_password")
            
            logger.debug(f"Password change attempt for user: {auth.current_user()}")
            
            if not all([current_password, new_password, confirm_password]):
                flash("All fields are required", "error")
                return redirect(url_for("change_password"))
                
            if new_password != confirm_password:
                flash("New passwords do not match", "error")
                return redirect(url_for("change_password"))
                
            success, message = change_admin_password(current_password, new_password)
            if success:
                # Update the in-memory users dictionary
                global users
                users = load_config().get("users", {})
                logger.info(f"Password successfully changed for user: {auth.current_user()}")
            else:
                logger.warning(f"Failed to change password for user: {auth.current_user()}, reason: {message}")
            
            flash(message, "success" if success else "error")
            return redirect(url_for("index"))
            
        return render_template("change_password.html")
    except Exception as e:
        logger.error(f"Error in change_password route: {str(e)}", exc_info=True)
        flash("An error occurred while changing the password. Please try again.", "error")
        return redirect(url_for("index"))

# TAXII Discovery
@app.route("/taxii2/", methods=["GET"])
def discovery():
    response = {
        "title": "Custom TAXII 2.1 Server",
        "description": "Web-enabled threat intel server",
        "api_roots": [
            "https://carried-lonely-design-bent.trycloudflare.com/taxii2/root/"
        ]
    }
    r = make_response(jsonify(response))
    r.headers["Content-Type"] = "application/taxii+json;version=2.1; charset=UTF-8"
    return r

# API Root Info
@app.route("/taxii2/root/", methods=["GET"])
def api_root():
    response = {
        "id": "api-root-001",
        "title": "Default API Root",
        "description": "Default API Root",
        "versions": ["application/taxii+json;version=2.1"],
        "supported_stix_versions": ["2.1"],
        "max_content_length": 10485760,
        "is_read_only": False,
    }
    r = make_response(jsonify(response))
    r.headers["Content-Type"] = "application/taxii+json;version=2.1; charset=UTF-8"
    return r

# List Collections
@app.route("/taxii2/root/collections/", methods=["GET"])
def list_collections():
    response = {
        "collections": [
            {
                "id": "default",
                "title": "IOC Collection",
                "can_read": True,
                "can_write": True,
                "supported_stix_versions": ["2.1"]
            }
        ]
    }
    r = make_response(jsonify(response))
    r.headers["Content-Type"] = "application/taxii+json;version=2.1; charset=UTF-8"
    return r

# STIX objects access
@app.route("/taxii2/root/collections/default/objects/", methods=["GET", "POST"])
def taxii_objects():
    if request.method == "GET":
        if os.path.exists(DATA_PATH):
            with open(DATA_PATH) as f:
                return json.load(f)
        return {"objects": []}

    if request.method == "POST":
        data = request.get_json()
        current = {"objects": []}
        if os.path.exists(DATA_PATH):
            with open(DATA_PATH) as f:
                current = json.load(f)
        current["objects"].extend(data["objects"])
        with open(DATA_PATH, "w") as f:
            json.dump(current, f)
        return "", 202

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    # Only set SERVER_NAME in production (Cloudflare) environment
    if os.environ.get('FLASK_ENV') != 'development':
        app.config['SERVER_NAME'] = 'carried-lonely-design-bent.trycloudflare.com'
        app.config['PREFERRED_URL_SCHEME'] = 'https'
    else:
        app.config['SERVER_NAME'] = None  # Don't set SERVER_NAME in development
    app.run(host="0.0.0.0", port=5000)
