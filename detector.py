import pandas as pd
import requests
from geopy.distance import geodesic
import json
import os
import sqlite3
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# -----------------------------
# CONFIG
# -----------------------------
SPEED_THRESHOLD = 900

# -----------------------------
# DATABASE SETUP
# -----------------------------
conn = sqlite3.connect("database/travel_detector.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    previous_ip TEXT,
    current_ip TEXT,
    distance_km REAL,
    speed_kmh REAL,
    risk_score INTEGER,
    severity TEXT
)
""")

conn.commit()

# -----------------------------
# LOAD VPN KEYWORDS
# -----------------------------
vpn_keywords = []

if os.path.exists("vpn_keywords.txt"):
    with open("vpn_keywords.txt", "r") as file:
        vpn_keywords = [line.strip().lower() for line in file]

# -----------------------------
# LOAD TRUSTED IPS
# -----------------------------
trusted_ips = set()

if os.path.exists("trusted_ips.txt"):
    with open("trusted_ips.txt", "r") as file:
        trusted_ips = set(line.strip() for line in file)

# -----------------------------
# GEO CACHE
# -----------------------------
geo_cache = {}

if os.path.exists("geo_cache.json"):
    try:
        with open("geo_cache.json", "r") as cache_file:
            geo_cache = json.load(cache_file)
    except json.JSONDecodeError:
        geo_cache = {}

# -----------------------------
# ALERT STORAGE
# -----------------------------
alerts = []

# -----------------------------
# USER BASELINE STORAGE
# -----------------------------
user_countries = {}

# -----------------------------
# GEOLOCATION FUNCTION
# -----------------------------
def get_location(ip):

    if ip in trusted_ips:
        return None

    if ip in geo_cache:
        return geo_cache[ip]

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        ).json()

        if response["status"] == "success":

            location_data = {
                "lat": response["lat"],
                "lon": response["lon"],
                "country": response["country"],
                "isp": response.get("isp", "Unknown")
            }

            geo_cache[ip] = location_data

            return location_data

    except Exception as e:
        print(f"{Fore.RED}Error fetching IP {ip}: {e}")

    return None

# -----------------------------
# VPN DETECTION
# -----------------------------
def is_suspicious_isp(isp_name):

    isp_name = isp_name.lower()

    for keyword in vpn_keywords:
        if keyword in isp_name:
            return True

    return False

# -----------------------------
# LOAD LOGIN DATA
# -----------------------------
df = pd.read_csv("sample_logins.csv")

df["timestamp"] = pd.to_datetime(df["timestamp"])

df = df.sort_values(by=["username", "timestamp"])

# -----------------------------
# DETECTION ENGINE
# -----------------------------
for username in df["username"].unique():

    user_logins = df[df["username"] == username]

    previous_login = None

    for _, row in user_logins.iterrows():

        current_login = {
            "ip": row["ip"],
            "timestamp": row["timestamp"]
        }

        if previous_login:

            loc1 = get_location(previous_login["ip"])
            loc2 = get_location(current_login["ip"])

            if loc1 and loc2:

                coords1 = (loc1["lat"], loc1["lon"])
                coords2 = (loc2["lat"], loc2["lon"])

                distance_km = geodesic(coords1, coords2).km

                time_diff_hours = (
                    current_login["timestamp"] -
                    previous_login["timestamp"]
                ).total_seconds() / 3600

                if time_diff_hours > 0:

                    speed = distance_km / time_diff_hours

                    risk_score = 0

                    # -----------------------------
                    # RISK FACTORS
                    # -----------------------------
                    if speed > SPEED_THRESHOLD:
                        risk_score += 50

                    if loc1["country"] != loc2["country"]:
                        risk_score += 20

                    if is_suspicious_isp(loc2.get("isp", "Unknown")):
                        risk_score += 30

                    # User baseline behavior
                    if username not in user_countries:
                        user_countries[username] = set()

                    if loc2["country"] not in user_countries[username]:
                        risk_score += 15

                    user_countries[username].add(loc2["country"])

                    # -----------------------------
                    # SEVERITY
                    # -----------------------------
                    severity = "LOW"

                    if risk_score >= 80:
                        severity = "CRITICAL"
                    elif risk_score >= 60:
                        severity = "HIGH"
                    elif risk_score >= 30:
                        severity = "MEDIUM"

                    print(f"\n{Fore.CYAN}================================")
                    print(f"{Fore.YELLOW}USER: {username}")
                    print(f"{Fore.WHITE}FROM: {previous_login['ip']} ({loc1['country']})")
                    print(f"{Fore.WHITE}TO:   {current_login['ip']} ({loc2['country']})")
                    print(f"{Fore.WHITE}ISP:  {loc2.get('isp', 'Unknown')}")
                    print(f"{Fore.WHITE}DISTANCE: {distance_km:.2f} km")
                    print(f"{Fore.WHITE}TIME: {time_diff_hours:.2f} hours")
                    print(f"{Fore.WHITE}SPEED: {speed:.2f} km/h")
                    print(f"{Fore.MAGENTA}RISK SCORE: {risk_score}")
                    print(f"{Fore.RED}SEVERITY: {severity}")

                    # -----------------------------
                    # ALERT CONDITION
                    # -----------------------------
                    if risk_score >= 40:

                        alert = {
                            "username": username,
                            "previous_ip": previous_login["ip"],
                            "current_ip": current_login["ip"],
                            "distance_km": round(distance_km, 2),
                            "speed_kmh": round(speed, 2),
                            "risk_score": risk_score,
                            "severity": severity,
                            "isp": loc2["isp"]
                        }

                        alerts.append(alert)

                        # Save to SQLite
                        cursor.execute("""
                        INSERT INTO alerts (
                            username,
                            previous_ip,
                            current_ip,
                            distance_km,
                            speed_kmh,
                            risk_score,
                            severity
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (
                            username,
                            previous_login["ip"],
                            current_login["ip"],
                            distance_km,
                            speed,
                            risk_score,
                            severity
                        ))

                        conn.commit()

                        print(f"{Fore.RED}ALERT GENERATED!")

        previous_login = current_login

# -----------------------------
# SAVE ALERTS JSON
# -----------------------------
with open("output/alerts.json", "w") as output_file:
    json.dump(alerts, output_file, indent=4)

# -----------------------------
# SAVE GEO CACHE
# -----------------------------
with open("geo_cache.json", "w") as cache_file:
    json.dump(geo_cache, cache_file, indent=4)

# -----------------------------
# SUMMARY
# -----------------------------
print(f"\n{Fore.GREEN}================================")
print(f"{Fore.GREEN}Total Alerts: {len(alerts)}")
print(f"{Fore.GREEN}Alerts saved to SQLite database")
print(f"{Fore.GREEN}Alerts saved to JSON")
print(f"{Fore.GREEN}Geo cache updated")

# Close DB connection
conn.close()