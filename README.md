# 🛡️ TAXII 2.1 Threat Intel Server (STIX 2.1 Compatible)

This is a fully operational **TAXII 2.1 server with STIX 2.1 support**, designed for:
- Manual or bulk IOC ingestion (Excel `.xlsx`)
- Indicator sharing over the TAXII protocol
- Web UI for IOC management
- Verified integration with **Secureworks Taegis XDR**
- Secure password management with bcrypt hashing

---

## 🎯 Features

| Feature                    | Description                                      |
|----------------------------|--------------------------------------------------|
| ✅ Web UI                 | Add/delete IOCs with secure authentication       |
| ✅ Excel Upload           | `.xlsx` import for bulk IOC input                |
| ✅ IOC Support            | IPs, domains, URLs, hashes (MD5/SHA1/SHA256)     |
| ✅ STIX 2.1 Generation     | Valid Indicator objects                          |
| ✅ TAXII 2.1 Endpoints     | Compliant and authenticated                      |
| ✅ Cloudflare Tunnel       | HTTPS access with no open ports                  |
| ✅ Taegis XDR Compatible   | Fully validated & integrated                     |
| ✅ Secure Auth            | Bcrypt password hashing & secure storage         |
| ✅ Dark Mode              | Modern UI with dark/light theme support          |

---

## 🧱 Project Structure

```
taxii-server/
├── app/
│   ├── main.py               # Main Flask app
│   ├── config.py            # Configuration & password management
│   ├── templates/
│   │   ├── base.html        # Base template with navigation
│   │   ├── index.html       # Main dashboard
│   │   └── change_password.html  # Password management
│   ├── requirements.txt
│   └── Dockerfile
├── data/                     # Secure storage for config & STIX bundles
│   ├── config.json          # Hashed passwords (auto-generated)
│   └── collection.json      # STIX bundle storage
├── docker-compose.yml
└── README.md
```

---

## 🔐 Security Features

- Passwords are securely hashed using bcrypt
- Configuration stored in separate `data/config.json`
- HTTPS enforced in production
- Flash messages for secure user feedback
- Environment-based configuration
- Proper file permissions handling
- Secure session management

---

## 🚀 How to Run

### 1. Clone or Download

```bash
git clone <your-repo-url>
cd taxii-server
```

### 2. Set Up Security

Generate secure keys and set up the environment:

```bash
# Generate a secure Flask secret key
export FLASK_SECRET_KEY=$(openssl rand -hex 32)

# Set your admin password
export ADMIN_PASSWORD="your-secure-password"

# Ensure proper permissions
mkdir -p data
chmod 755 data
```

### 3. Start with Docker

```bash
# Build and start the container
docker-compose up -d --build
```

Web UI: [http://localhost:5050](http://localhost:5050)  
Login: `admin` / (your chosen password)

> **Security Notes**: 
> - The admin password is stored securely using bcrypt hashing in `data/config.json`
> - The Flask secret key is used for secure session management
> - Make sure to keep both the `data` directory and environment variables secure
> - Never commit `data/config.json` or expose your environment variables

### 4. Change Admin Password

You can change the admin password in two ways:

1. **Through the Web UI**:
   - Log in to the web interface
   - Click "Change Password" in the top navigation
   - Enter current and new password
   - Click "Change Password"

2. **Through Environment Variable** (if you need to reset):
   ```bash
   # Stop the container
   docker-compose down
   
   # Set new password
   export ADMIN_PASSWORD="your-new-password"
   
   # Remove existing config
   rm data/config.json
   
   # Restart container
   docker-compose up -d
   ```

---

## 📤 TAXII 2.1 API

| Endpoint                              | Description                |
|--------------------------------------|----------------------------|
| `/taxii2/`                            | Discovery endpoint         |
| `/taxii2/root/`                       | API root with STIX support |
| `/taxii2/root/collections/`          | Lists collections          |
| `/taxii2/root/collections/default/objects/` | Access/submit objects     |

All endpoints respond with:
```
Content-Type: application/taxii+json;version=2.1; charset=UTF-8
```

---

## ✅ Taegis XDR Integration

**Required settings:**

| Field               | Value                                                             |
|---------------------|-------------------------------------------------------------------|
| Root URL            | `https://<your-tunnel>.trycloudflare.com/taxii2/root/`           |
| Collection ID       | `default`                                                        |
| Username / Password | `admin` / (your chosen password)                                 |

**Notes:**
- Must include: `versions: ["application/taxii+json;version=2.1"]`
- Must declare: `supported_stix_versions: ["2.1"]`
- Collections must be provided at `/collections/`, not embedded in `/root/`

---

## 🌐 Public Access (Cloudflare Tunnel)

```bash
# Install cloudflared
brew install cloudflared

# Start tunnel
cloudflared tunnel --url http://localhost:5050
```

Copy the public HTTPS link. This makes your TAXII server securely accessible from anywhere.

---

## 🧪 Validate With Python Client

```bash
pip install taxii2-client
```

```python
from taxii2client.v21 import Server
from requests.auth import HTTPBasicAuth

server = Server(
    'https://your-tunnel.trycloudflare.com/taxii2/',
    auth=HTTPBasicAuth('admin', 'your-password'),
    verify=False
)
api_root = server.api_roots[0]
for c in api_root.collections:
    print(c.title, c.id)
```

---

## 🔧 Troubleshooting

### Common Issues

1. **Password Change Fails**:
   - Check `docker-compose logs` for detailed error messages
   - Ensure `data` directory has proper permissions (755)
   - Verify `FLASK_SECRET_KEY` is set
   - Check if `config.json` is writable

2. **Authentication Issues**:
   - Verify `ADMIN_PASSWORD` is set correctly
   - Check if `config.json` exists and is readable
   - Ensure proper file permissions

3. **Cloudflare Tunnel Issues**:
   - Verify the tunnel is running
   - Check if the server is accessible locally
   - Ensure proper SERVER_NAME configuration

---

## 🛠️ Next Ideas

- CSV upload support
- Multiple collections
- STIX bundle export
- Stats dashboard
- Feed notification webhook
- Multi-user support
- API key authentication

---

## 🙌 Credit

Built with ❤️ by Ștefan, with guidance from OpenAI ChatGPT.

Validated by:
- `curl`
- `taxii2-client`
- `Secureworks Taegis XDR`
