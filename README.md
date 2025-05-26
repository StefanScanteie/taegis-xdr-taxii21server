
# 🛡️ TAXII 2.1 Threat Intel Server (STIX 2.1 Compatible)

This is a fully operational **TAXII 2.1 server with STIX 2.1 support**, designed for:
- Manual or bulk IOC ingestion (Excel `.xlsx`)
- Indicator sharing over the TAXII protocol
- Web UI for IOC management
- ✅ Verified integration with **Secureworks Taegis XDR**

---

## 🎯 Features

| Feature                    | Description                                      |
|----------------------------|--------------------------------------------------|
| ✅ Web UI                 | Add/delete IOCs with basic auth                  |
| ✅ Excel Upload           | `.xlsx` import for bulk IOC input                |
| ✅ IOC Support            | IPs, domains, URLs, hashes (MD5/SHA1/SHA256)     |
| ✅ STIX 2.1 Generation     | Valid Indicator objects                          |
| ✅ TAXII 2.1 Endpoints     | Compliant and authenticated                      |
| ✅ Cloudflare Tunnel       | HTTPS access with no open ports                  |
| ✅ Taegis XDR Compatible   | Fully validated & integrated                     |

---

## 🧱 Project Structure

```
taxii-server/
├── app/
│   ├── main.py               # Main Flask app
│   ├── templates/
│   │   └── index.html        # Tailwind-based UI
│   ├── requirements.txt
│   └── Dockerfile
├── data/                     # STIX bundle storage
├── docker-compose.yml
├── README.md
```

---

## 🚀 How to Run

### 1. Clone or Download

```bash
git clone <your-repo-url>
cd taxii-server
```

---

### 2. Start with Docker

```bash
docker-compose up -d --build
```

Web UI: [http://localhost:5050](http://localhost:5050)  
Login: `admin` / `adminpass`

---

### 3. Use the Web UI

- Submit IOCs manually
- Upload Excel files (`.xlsx`) with `value`, `Threat Desc`, and `Published Date`
- Delete old IOCs on demand

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
| Username / Password | `admin` / `adminpass`                                            |

**Notes:**
- Must include: `versions: ["application/taxii+json;version=2.1"]`
- Must declare: `supported_stix_versions: ["2.1"]`
- Collections must be provided at `/collections/`, not embedded in `/root/`

---

## 🌐 Public Access (Cloudflare Tunnel)

```bash
brew install cloudflared
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
  auth=HTTPBasicAuth('admin', 'adminpass'),
  verify=False
)
api_root = server.api_roots[0]
for c in api_root.collections:
    print(c.title, c.id)
```

---

## 🛠️ Next Ideas

- CSV upload
- Multiple collections
- STIX bundle export
- Dark mode UI
- Stats dashboard
- Feed notification webhook

---

## 🙌 Credit

Built with ❤️ by Ștefan, with guidance from OpenAI ChatGPT.

Validated by:
- `curl`
- `taxii2-client`
- ✅ **Secureworks Taegis XDR**
