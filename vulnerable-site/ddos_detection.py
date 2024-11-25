import pyshark
import threading
import time
import requests
from datetime import datetime

DASHBOARD_URL = "http://dashboard:5001/report-attack"
CAPTURE_INTERFACE = 'eth0'
VULNERABLE_SITE_IP = '172.30.0.10'
DDOS_PACKET_THRESHOLD = 100

def report_attack(attack_type):
    try:
        data = {
            'type': attack_type,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        response = requests.post(DASHBOARD_URL, json=data)
        if response.status_code == 200:
            print(f"Successfully reported {attack_type} attack to dashboard.")
        else:
            print(f"Failed to report attack: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error reporting attack: {e}")

def monitor_packets():
    capture = pyshark.LiveCapture(interface=CAPTURE_INTERFACE, display_filter=f'ip.dst == {VULNERABLE_SITE_IP}')
    packet_count = 0
    start_time = time.time()

    for packet in capture.sniff_continuously():
        packet_count += 1
        elapsed_time = time.time() - start_time

        if elapsed_time >= 60:  # Check every 60 seconds
            if packet_count > DDOS_PACKET_THRESHOLD:
                print(f"DDoS attack detected with {packet_count} packets in the last minute.")
                report_attack("DDoS")
            else:
                print(f"No DDoS attack detected. Packet count: {packet_count}")
            packet_count = 0
            start_time = time.time()

def start_ddos_detection():
    detection_thread = threading.Thread(target=monitor_packets, daemon=True)
    detection_thread.start()
    print("DDoS detection thread started.")
