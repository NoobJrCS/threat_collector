# 🛡️ ThreatFox IOC Intelligence Dashboard

A full-featured threat intelligence dashboard that collects, enriches, and visualizes Indicators of Compromise (IOCs) from [abuse.ch ThreatFox](https://threatfox.abuse.ch/), complete with GeoIP mapping, risk scoring, and real-time visualization.

---

## 🚀 Features

✅ IOC collection from ThreatFox (API)  
✅ SQLite-backed IOC database  
✅ GeoIP enrichment (country, org, ASN, lat/lon)  
✅ Automatic risk scoring (High Risk, Suspicious, Normal)  
✅ Leaflet.js world map with live IOC pins  
✅ Fully interactive Flask dashboard  
✅ Table with IOC types, timestamps, orgs, and threats  
✅ Bootstrap-based UI with tooltips and row coloring



## 📦 Project Structure

```bash
threat_collector/
├── collector.py       # Main IOC collector + enrichment script
├── app.py             # Flask web app
├── ioc_collector.db   # SQLite database of enriched IOCs
├── templates/
│   └── index.html     # Dashboard HTML (Jinja2)
├── static/
│   └── (optional JS/CSS)
└── env/               # Python virtual environment
