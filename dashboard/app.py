from flask import Flask, request, jsonify, render_template
import sqlite3

app = Flask(__name__)

# SQLite database file path
DB_PATH = '/persistent/dashboard.db'

# Function to load system status from the database
def load_system_status():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT network_status, ml_detection_status, last_updated FROM system_status ORDER BY id DESC LIMIT 1')
    status = cur.fetchone()
    conn.close()
    
    if status:
        return {
            "network_status": status[0] if status[0] else "Unknown",
            "ml_detection_status": status[1] if status[1] else "Not Started",
            "last_updated": status[2] if status[2] else "N/A"
        }
    else:
        # Return default if no data is found
        return {
            "network_status": "Unknown",
            "ml_detection_status": "Not Started",
            "last_updated": "N/A"
        }

# Function to load attack logs from the database
def load_attack_logs():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT attack_type, timestamp FROM attack_logs ORDER BY timestamp DESC')
    logs = cur.fetchall()
    conn.close()

    return [{"attack_type": log[0], "timestamp": log[1]} for log in logs]

@app.route('/')
def index():
    system_status = load_system_status()
    attack_logs = load_attack_logs()

    sql_injection_count = len([log for log in attack_logs if log['attack_type'] == 'SQL Injection'])
    ddos_count = len([log for log in attack_logs if log['attack_type'] == 'DDoS'])
    xss_count = len([log for log in attack_logs if log['attack_type'] == 'XSS'])

    return render_template('index.html', 
                           network_status=system_status["network_status"], 
                           ml_status=system_status["ml_detection_status"],
                           sql_injection_count=sql_injection_count,
                           ddos_count=ddos_count,
                           xss_count=xss_count,
                           attack_logs=attack_logs)

# Endpoint to log attacks
@app.route('/report-attack', methods=['POST'])
def report_attack():
    try:
        # Get data from the POST request
        attack_data = request.json
        attack_type = attack_data.get('type')
        timestamp = attack_data.get('timestamp')
        
        # Debugging log to check if API received the request
        print(f"Received attack type: {attack_type}, at {timestamp}")
        
        # Insert attack into database
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('INSERT INTO attack_logs (attack_type, timestamp) VALUES (?, ?)', (attack_type, timestamp))
        conn.commit()
        conn.close()

        return jsonify({"status": "Attack logged successfully"}), 200
    except Exception as e:
        print(f"Error logging attack: {e}")
        return jsonify({"status": "Error logging attack", "error": str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
