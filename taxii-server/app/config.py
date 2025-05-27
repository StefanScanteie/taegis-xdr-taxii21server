import os
from werkzeug.security import generate_password_hash, check_password_hash
import json

API_ROOT = "/taxii2"
COLLECTION_PATH = os.path.join(os.getcwd(), "data", "collection.json")
CONFIG_PATH = os.path.join(os.getcwd(), "data", "config.json")

def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    return {"users": {}}

def save_config(config):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f)

def setup_admin_password(password):
    config = load_config()
    config["users"] = {
        "admin": generate_password_hash(password)
    }
    save_config(config)
    return config["users"]

def change_admin_password(current_password, new_password):
    config = load_config()
    if "admin" not in config.get("users", {}):
        return False, "Admin user not found"
    
    if not check_password_hash(config["users"]["admin"], current_password):
        return False, "Current password is incorrect"
    
    config["users"]["admin"] = generate_password_hash(new_password)
    save_config(config)
    return True, "Password updated successfully"
