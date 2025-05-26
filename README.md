
# 📦 TAXII 2.1 Threat Intel Server with Web UI

This project is a **fully functional TAXII 2.1 server** that lets you:

- 🔐 Submit IOCs via web form (authenticated)
- 📤 Upload Excel files (`.xlsx`) to bulk import IOCs
- 📄 Auto-generate STIX 2.1 Indicator objects
- 🧹 Delete IOCs from the web UI
- 🎨 Use a modern Tailwind-styled frontend
- ⚡ Serve data to external tools like **Taegis XDR**

---

## 🖼️ Features

| Feature                          | Description                                      |
|----------------------------------|--------------------------------------------------|
| ✅ Web UI                        | For submitting and viewing IOCs                 |
| ✅ Excel Upload (`.xlsx`)        | Supports NCSC-style IOC files                   |
| ✅ IOC Classification            | IPs, domains, hashes, URLs                      |
| ✅ STIX 2.1 Conversion            | Valid indicators with correct patterns          |
| ✅ TAXII 2.1 API                 | `/taxii2/` + `/taxii2/root/collections/...`     |
| ✅ Basic Auth                    | Protects the web UI (`admin:adminpass`)         |
| ✅ Delete Button                 | Remove IOCs on demand                           |

---

## 🧱 Project Structure

```
taxii-server/
├── app/
│   ├── main.py               # Flask + STIX + TAXII logic
│   ├── templates/
│   │   └── index.html        # Tailwind UI
│   ├── requirements.txt
│   └── Dockerfile
├── data/                     # IOC storage (STIX bundle JSON)
├── docker-compose.yml
```

---

## 🚀 How to Run It

### 1. Clone or Download

```bash
git clone <your-repo-url>
cd taxii-server
```

Or just download the folder if you built locally.

---

### 2. Build and Run

```bash
docker-compose up -d --build
```

Open: [http://localhost:5050](http://localhost:5050)

🔐 Login:  
- **Username:** `admin`  
- **Password:** `adminpass`

---

### 3. Submit IOCs

#### ✅ Web Form (Manual Entry)

- IPs (e.g. `192.168.0.1`)
- Domains (e.g. `malicious.com`)
- Hashes (MD5, SHA-1, SHA-256)
- URLs (e.g. `http://bad.site/path`)

You can obfuscate with `[.]` — it will be sanitized.

#### ✅ Excel Upload

Upload `.xlsx` files containing a table like:

| value             | Threat Desc           | Published Date      |
|------------------|------------------------|---------------------|
| 8.8.8.8          | test IP                | 2025-05-26 14:30:00 |
| bad[.]com        | phishing domain        | 2025-05-25 09:00:00 |

---

## 🔁 TAXII 2.1 API Endpoints

- Discovery: `http://localhost:5050/taxii2/`
- API Root: `http://localhost:5050/taxii2/root/`
- Objects:
  ```http
  GET/POST http://localhost:5050/taxii2/root/collections/default/objects/
  ```

All data is saved to: `data/collection.json` in STIX 2.1 format.

---

## 🧪 Example STIX Pattern Detection

| Input                    | Pattern Type     |
|-------------------------|------------------|
| `192.0.2.1`             | ipv4-addr        |
| `evil[.]site`           | domain-name      |
| `http://1.2.3.4/abc`    | url              |
| `8650be1565...`         | file:hashes.MD5  |

---

## 🧼 Tips

- Ensure Excel files have no empty rows at the end
- "Threat Desc" is optional, but improves context
- Missing dates default to `datetime.utcnow()`

---

## ✅ Coming Soon (Optional Add-ons)

- CSV upload support
- Multi-user authentication
- IOC search + filtering
- IOC expiration logic
- Export STIX bundles
