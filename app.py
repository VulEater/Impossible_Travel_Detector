from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

@app.route("/")
def dashboard():

    conn = sqlite3.connect("database/travel_detector.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT username,
           previous_ip,
           current_ip,
           speed_kmh,
           risk_score,
           severity
    FROM alerts
    ORDER BY id DESC
    """)

    alerts = cursor.fetchall()

    conn.close()

    return render_template("dashboard.html", alerts=alerts)

if __name__ == "__main__":
    app.run(debug=True)