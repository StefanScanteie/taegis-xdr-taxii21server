from flask import Flask, request, render_template, redirect, url_for
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from stix2 import Indicator
from datetime import datetime
import json
import os
import re
import pandas as pd
from io import BytesIO

app = Flask(__name__)
auth = HTTPBasicAuth()

# Basic Auth credentials
users = {
    "admin": generate_password_hash("adminpass")
}

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

                # Safe date parse with fallback
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

            if os.path.exists(DATA_PATH):
                with open(DATA_PATH) as f:
                    current = json.load(f)
            else:
                current = {"objects": []}

            current["objects"].extend(json.loads(i.serialize()) for i in indicators)

            with open(DATA_PATH, "w") as f:
                json.dump(current, f)
            return redirect(url_for("index"))

        # Manual entry fallback
        ioc_value = request.form.get("ioc", "").strip()
        threat = request.form.get("threat", "Manual Entry")
        if ioc_value:
            ioc_type, pattern = classify_ioc(ioc_value)
            indicator = Indicator(
                name=f"IOC: {ioc_value}",
                pattern=pattern,
                pattern_type="stix",
                valid_from=datetime.utcnow().isoformat() + "Z",
                description=threat
            )

            if os.path.exists(DATA_PATH):
                with open(DATA_PATH) as f:
                    current = json.load(f)
            else:
                current = {"objects": []}

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

@app.route("/taxii2/", methods=["GET"])
def discovery():
    return {
        "title": "Custom TAXII 2.1 Server",
        "description": "Web-enabled threat intel server",
        "default": "http://localhost:5050/taxii2/root/"
    }

@app.route("/taxii2/root/", methods=["GET"])
def api_root():
    return {
        "title": "Default API Root",
        "description": "IOC collection",
        "collections": [
            {
                "id": "default",
                "title": "IOC Collection",
                "can_read": True,
                "can_write": True
            }
        ]
    }

@app.route("/taxii2/root/collections/default/objects/", methods=["GET", "POST"])
def taxii_objects():
    if request.method == "GET":
        if os.path.exists(DATA_PATH):
            with open(DATA_PATH) as f:
                return json.load(f)
        return {"objects": []}

    if request.method == "POST":
        data = request.get_json()
        if os.path.exists(DATA_PATH):
            with open(DATA_PATH) as f:
                current = json.load(f)
        else:
            current = {"objects": []}
        current["objects"].extend(data["objects"])
        with open(DATA_PATH, "w") as f:
            json.dump(current, f)
        return "", 202

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    app.run(host="0.0.0.0", port=5000)
