import schedule
import time
import json
import logging
import requests
import subprocess
from scapy.all import rdpcap
from datetime import datetime
import sqlite3

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Paths for status updates and Kitsune report (stored in a persistent volume)
STATUS_FILE_PATH = '/persistent/status.json'  # Use /persistent volume for persistence
KITSUNE_REPORT_PATH = '/persistent/kitsune_report.json'
DB_PATH = '/persistent/dashboard.db'

# Initialize status if no file exists
status_data = {
    "network_status": "Unknown",
    "ml_detection_status": "Not Started",
    "attack_stats": {
        "XSS": 0,
        "SQL Injection": 0,
        "DDoS": 0
    },
    "attack_log": []
}

# Load status at the start of the script
def load_status():
    global status_data
    try:
        if os.path.exists(STATUS_FILE_PATH):
            with open(STATUS_FILE_PATH, 'r') as f:
                status_data = json.load(f)
            logging.debug("Status loaded from JSON file.")
        else:
            logging.debug("No status file found. Using default values.")
    except Exception as e:
        logging.error(f"Error loading status: {e}")

# Helper function to save status data to JSON file
def save_status():
    try:
        with open(STATUS_FILE_PATH, 'w') as f:
            json.dump(status_data, f)
        logging.debug("Status saved to JSON file.")
    except Exception as e:
        logging.error(f"Error saving status: {e}")

# Function to save attack logs to the database
def save_attack_log(attack_type, timestamp):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('INSERT INTO attack_logs (attack_type, timestamp) VALUES (?, ?)', (attack_type, timestamp))
    conn.commit()
    conn.close()

# Function to update ML Detection status in the database
def update_ml_status(status):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('UPDATE system_status SET ml_detection_status = ?, last_updated = ? WHERE id = (SELECT MAX(id) FROM system_status)', 
                (status, datetime.now()))
    conn.commit()
    conn.close()

# Function to check network status
def check_network_status():
    logging.debug("Checking network status...")
    try:
        response = requests.get('http://vulnerable-site:5000', timeout=5)  # Update with Docker service name
        if response.status_code == 200:
            status_data["network_status"] = "Active"
        else:
            status_data["network_status"] = "Down"
    except Exception as e:
        logging.error(f"Network status check failed: {e}")
        status_data["network_status"] = "Down"
    
    # Save updated status
    save_status()

# Function to run Kitsune and update ML Detection status
def run_kitsune():
    logging.debug("Running Kitsune anomaly detection...")
    try:
        # Set status to Running
        status_data["ml_detection_status"] = "Running..."
        save_status()  # Save running status immediately

        # Example paths - adjust as needed
        pcap_file = "/app/pcap_files/healthcare.pcapng"
        kitsune_script = "/app/Kitsune-py/Kitsune.py"

        # Determine packet limit based on file
        packet_limit = count_packets(pcap_file)
        logging.debug(f"Packet limit for Kitsune: {packet_limit}")

        # Run Kitsune script
        result = subprocess.run(
            ['python', kitsune_script, pcap_file, str(packet_limit)],
            capture_output=True, text=True
        )

        logging.debug(f"Kitsune stdout: {result.stdout}")
        logging.debug(f"Kitsune stderr: {result.stderr}")

        # Extract anomalies detected
        anomaly_count = extract_anomalies(result.stdout)
        logging.debug(f"Anomalies detected: {anomaly_count}")

        # Update DDoS attack count in the status
        status_data["attack_stats"]["DDoS"] = anomaly_count

        # Mark ML Detection as Operational after running successfully
        status_data["ml_detection_status"] = "Operational"

        # Append DDoS detection to attack log
        if anomaly_count > 0:
            status_data["attack_log"].append(f"DDoS attack detected with {anomaly_count} anomalies at {datetime.now()}")
            save_attack_log('DDoS', datetime.now())  # Save attack log to DB

        # Update ML Detection status in the database
        update_ml_status("Operational")

    except Exception as e:
        logging.error(f"Error running Kitsune: {e}")
        status_data["ml_detection_status"] = "Failed"
        update_ml_status("Failed")

    # Save updated status
    save_status()

# Helper functions
def count_packets(filepath):
    try:
        packets = rdpcap(filepath)
        return len(packets)
    except Exception as e:
        logging.error(f"Error counting packets with Scapy: {e}")
        return 1000  # Default limit on error

def extract_anomalies(kitsune_output):
    try:
        lines = kitsune_output.split('\n')
        for line in lines:
            if "Anomalies detected" in line:
                return int(line.split(":")[-1].strip())
        return 0
    except Exception as e:
        logging.error(f"Error extracting anomalies from Kitsune output: {e}")
        return 0

# Schedule tasks
schedule.every(1).minutes.do(check_network_status)
schedule.every(30).minutes.do(run_kitsune)

run_kitsune()  # Manually trigger Kitsune once for testing

# Start the scheduler
while True:
    schedule.run_pending()
    time.sleep(1)
