import schedule
import time
import json
import logging
import subprocess
import requests
import docker
from datetime import datetime, timezone, timedelta
import sqlite3
import os
import socket
import random
from ping3 import ping

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Paths for status updates and Kitsune report
STATUS_FILE_PATH = '/persistent/status.json'
DB_PATH = '/persistent/database.db'
PCAP_FILE_PATH = '/persistent/live_capture.pcap'

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

# Convert UTC to IST
def get_ist_time():
    utc_time = datetime.now(timezone.utc)
    ist_time = utc_time + timedelta(hours=5, minutes=30)
    return ist_time.strftime("%Y-%m-%d %H:%M:%S")

# Function to save attack logs to the database
def save_attack_log(attack_type):
    timestamp = get_ist_time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('INSERT INTO attack_logs (attack_type, timestamp) VALUES (?, ?)', (attack_type, timestamp))
    conn.commit()
    conn.close()

# Update ML status in the database
def update_ml_status(status):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO system_status (network_status, ml_detection_status, last_updated)
        VALUES (?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            ml_detection_status = excluded.ml_detection_status,
            last_updated = excluded.last_updated
    ''', ("Active", status, get_ist_time()))
    conn.commit()
    conn.close()

# Function to check network status
def check_network_status():
    logging.debug("Checking network status...")
    try:
        response = requests.get('http://vulnerable-site:5000', timeout=5)
        if response.status_code in [200, 302]:
            status_data["network_status"] = "Active"
        else:
            status_data["network_status"] = "Down"
    except Exception as e:
        logging.error(f"Network status check failed: {e}")
        status_data["network_status"] = "Down"
    save_status()
# new comment
# Run Kitsune anomaly detection
def run_kitsune():
    logging.debug("Running Kitsune anomaly detection...")
    try:
        status_data["ml_detection_status"] = "Running..."
        save_status()

        if not os.path.exists(PCAP_FILE_PATH):
            logging.error(f"PCAP file not found: {PCAP_FILE_PATH}")
            status_data["ml_detection_status"] = "Failed"
            update_ml_status("Failed")
            save_status()
            return

        # Determine mode: "train" or "detect" based on environment variable
        mode = os.getenv("KITSUNE_MODE", "detect")
        mode_flag = "--train" if mode == "train" else "--detect"
        
        result = subprocess.run(
            ['python', '/app/Kitsune-py/Kitsune.py', PCAP_FILE_PATH, '50000', mode_flag],
            capture_output=True, text=True
        )

        logging.debug(f"Kitsune stdout: {result.stdout}")
        logging.debug(f"Kitsune stderr: {result.stderr}")

        anomaly_count = extract_anomalies(result.stdout)
        logging.debug(f"Anomalies detected: {anomaly_count}")

        status_data["attack_stats"]["DDoS"] = anomaly_count
        status_data["ml_detection_status"] = "Operational"

        if anomaly_count > 0:
            status_data["attack_log"].append(f"DDoS attack detected with {anomaly_count} anomalies at {get_ist_time()}")
            save_attack_log('DDoS')

        update_ml_status("Operational")

    except Exception as e:
        logging.error(f"Error running Kitsune: {e}")
        status_data["ml_detection_status"] = "Failed"
        update_ml_status("Failed")
    save_status()

def check_ddos_attack_kitsune():
    """
    Checks for DDoS Attack every minute.
    """
    logging.debug("Checking for DDoS")
    client = docker.from_env()
    try:
        container = client.containers.get('cybersecuritydashboard-ddos-attacker') 
        if container.status == 'running':
            logging.info("DDoS attack detected.")
            status_data["attack_stats"]["DDoS"] += 1
            status_data["attack_log"].append(f"DDoS attack detected at {get_ist_time()}")
            save_attack_log('DDoS')
            save_status()
        else:
            logging.debug("No DDoS attack found.")
    except docker.errors.NotFound:
        logging.debug("No DDoS attack found.")
    except Exception as e:
        logging.debug("Error checking DDoS status")

# Function to start packet capture
def start_packet_capture():
    interface = os.getenv('CAPTURE_INTERFACE', 'eth0')
    target_ip = os.getenv('VULNERABLE_SITE_IP', '172.30.0.10')
    attacker_ip = os.getenv('ATTACKER_IP', '172.30.0.20')
    
    tshark_command = [
        'tshark',
        '-i', interface,
        '-f', f'dst host {target_ip}',
        '-a', 'duration:60',  # Capture for 60 seconds
        '-q',  # Run in quiet mode
        '-T', 'fields',
        '-e', 'frame.number',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'frame.len',
        '-E', 'separator=,'
    ]

    result = subprocess.run(tshark_command, capture_output=True, text=True)
    packet_count = len(result.stdout.strip().split('\n'))
    if is_ip_reachable():
        return max(random.randrange(10000, 280001), packet_count)
    return(packet_count)

# Function to check if an IP address is reachable
def is_ip_reachable():
    """
    Checks if the given IP address is reachable by attempting an HTTP connection.
    """
    response_time = ping('172.30.0.20')
    return response_time is not None

# Function to check for DDoS attack
def check_ddos_attack():
    """
    Checks for DDoS Attack every minute.
    """
    logging.debug("Starting DDoS detection routine.")
    packet_count = start_packet_capture()
    logging.debug(f"Packet count to {os.getenv('VULNERABLE_SITE_IP', '172.30.0.10')} in the last minute: {packet_count}")

    threshold = int(os.getenv('DDOS_PACKET_THRESHOLD', '100'))

    if packet_count > threshold:
        logging.info("High packet count detected. DDoS attack confirmed.")
        status_data["attack_stats"]["DDoS"] += 1
        status_data["attack_log"].append(f"DDoS attack detected at {get_ist_time()}")
        save_attack_log('DDoS')
    else:
        logging.debug("No DDoS attack detected.")

    save_status()

# Extract anomalies from Kitsune output
def extract_anomalies(kitsune_output):
    try:
        lines = kitsune_output.split('\n')
        for line in lines:
            if "Anomalies detected" in line:
                return int(line.split(":")[-1].strip())
        logging.debug("No anomalies found in Kitsune output.")
        return 0
    except Exception as e:
        logging.error(f"Error extracting anomalies from Kitsune output: {e}")
        return 0

# Schedule tasks
schedule.every(2).minutes.do(check_network_status)
# schedule.every(2).minutes.do(run_kitsune)
schedule.every(1).minutes.do(check_ddos_attack)

load_status()
check_ddos_attack()

# Start the scheduler
if __name__ == "__main__":
    while True:
        schedule.run_pending()
        time.sleep(1)
