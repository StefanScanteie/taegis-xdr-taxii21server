from taxii2client.v21 import Server
from requests.auth import HTTPBasicAuth

server = Server(
    'https://carried-lonely-design-bent.trycloudflare.com/taxii2/',
    auth=HTTPBasicAuth('admin', 'your-password'),
    verify=False  # Set to True if using HTTPS with valid cert
)

# Print API roots
print("API Roots:")
for api_root in server.api_roots:
    print("-", api_root.url)

# Get the default root
api_root = server.api_roots[0]

# Get available collections
print("\nCollections:")
for collection in api_root.collections:
    print("-", collection.title, f"(ID: {collection.id})")
