from flask import Flask, render_template
import sqlite3
from collections import Counter

app = Flask(__name__)
DB_FILE = "ioc_collector.db"

# ✅ 1. Define all helper functions first

def get_iocs():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT ioc, type, threat_type, country, org, risk, timestamp FROM iocs ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def get_top_malware(limit=5):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT threat_type FROM iocs")
    rows = [row[0] for row in c.fetchall()]
    conn.close()
    top = Counter(rows).most_common(limit)
    return top

def get_coords():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT ioc, threat_type, country, org, risk, latitude, longitude FROM iocs WHERE latitude IS NOT NULL AND longitude IS NOT NULL")
    data = c.fetchall()
    conn.close()
    return data

# ✅ 2. Now define the route that uses those functions

@app.route("/")
def index():
    data = get_iocs()
    top_malware = get_top_malware()
    coords = get_coords()
    return render_template("index.html", data=data, top_malware=top_malware, coords=coords)

# ✅ 3. Main entrypoint

if __name__ == "__main__":
    app.run(debug=True)
