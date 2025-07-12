import requests
from datetime import datetime
import sqlite3
import os
import requests

def geoip_lookup(ip):
    print(f"[GeoIP] Looking up: {ip}")
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,org,as,lat,lon",
            timeout=5
        )
        data = response.json()
        if data['status'] == 'success':
            return {
                "country": data.get("country", ""),
                "org": data.get("org", ""),
                "asn": data.get("as", ""),
                "lat": data.get("lat"),
                "lon": data.get("lon")
            }
    except:
        pass
    return {
        "country": "Unknown", "org": "Unknown", "asn": "Unknown",
        "lat": None, "lon": None
    }



def get_risk_score(ioc_entry):
    risky_malware = ['Cobalt Strike', 'Lumma', 'Raccoon', 'Remcos', 'AgentTesla']
    if ioc_entry["threat_type"] in risky_malware:
        return "⚠ High Risk"
    if ioc_entry["type"] in ["url", "ip:port", "ip"]:
        return "⚠ Suspicious"
    return "Normal"



# ✅ Correct API endpoint
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"

# ✅ Required payload
PAYLOAD = {
    "query": "get_iocs",
    "days": 1,      # Optional: change to 7 for more IOCs
    "limit": 50     # Optional: increase if needed
}

# ✅ Your personal API key (keep it private!)
API_KEY = "API KEY HERE"

def fetch_threatfox_iocs():
    print("[*] Fetching IOCs from ThreatFox API...")
    headers = {
        "Auth-Key": API_KEY,
        "Content-Type": "application/json",
        "User-Agent": "ThreatIntelCollector/1.0"
    }

    try:
        response = requests.post(THREATFOX_API, headers=headers, json=PAYLOAD)
        print(f"[!] Status Code: {response.status_code}")

        if response.status_code != 200:
            print("[!] Bad HTTP response")
            print(response.text)
            return []

        json_data = response.json()
        if json_data.get("query_status") != "ok":
            print("[-] API query failed")
            return []

        iocs = []
        for entry in json_data["data"]:
            iocs.append({
                "source": "ThreatFox",
                "ioc": entry.get("ioc"),
                "type": entry.get("ioc_type"),
                "threat_type": entry.get("malware_printable"),
                "timestamp": datetime.utcnow().isoformat()
            })

        print(f"[+] Retrieved {len(iocs)} IOCs.")
        return iocs

    except Exception as e:
        print(f"[-] Error: {e}")
        return []
DB_FILE = "ioc_collector.db"

def init_db():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc TEXT,
                type TEXT,
                threat_type TEXT,
                source TEXT,
                timestamp TEXT
            )
        ''')
        conn.commit()
        conn.close()
        print("[+] SQLite DB created.")
        
def save_iocs(ioc_list):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    saved = 0

    for ioc in ioc_list:
        country = org = "Unknown"
        lat = lon = None

        if ioc["type"].startswith("ip"):
            ip_only = ioc["ioc"].split(":")[0]
            geo = geoip_lookup(ip_only)
            country = geo.get("country", "Unknown")
            org = geo.get("org", "Unknown")
            lat = geo.get("lat")
            lon = geo.get("lon")

        risk = get_risk_score(ioc)

        try:
            c.execute('''
                INSERT INTO iocs (ioc, type, threat_type, source, timestamp, country, org, risk, latitude, longitude)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ioc['ioc'], ioc['type'], ioc['threat_type'], ioc['source'],
                ioc['timestamp'], country, org, risk, lat, lon
            ))
            saved += 1
        except Exception as e:
            print(f"[-] Failed to insert {ioc['ioc']}: {e}")

    conn.commit()
    conn.close()
    print(f"[+] Saved {saved} enriched IOCs to DB.")


        

if __name__ == "__main__":
    init_db()
    iocs = fetch_threatfox_iocs()
    save_iocs(iocs)
    print("[*] First 5 IOCs:")
    for ioc in iocs[:5]:
        print(ioc)

