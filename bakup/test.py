import requests
import json

url = "https://discord.com/api/webhooks/1445820157883584512/HlbXs8nPx04Oipht1HHzorzvDSkn5IKhHGvEjxEr7yUrmB8WUcWUIFEFLg28WJl79qgG"
payload = {"content": "Test message"}
headers = {"Content-Type": "application/json"}

r = requests.post(url, headers=headers, data=json.dumps(payload))
print(r.status_code, r.text)