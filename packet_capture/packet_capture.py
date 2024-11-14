import pyshark
import schedule
import time
import logging
import os
import subprocess
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the interface and IP for vulnerable-site traffic
interface = os.getenv('CAPTURE_INTERFACE', 'eth0')
vulnerable_site_ip = os.getenv('VULNERABLE_SITE_IP', '172.22.0.10')  # Static IP for vulnerable-site
output_file = f'/persistent/live_capture.pcap'

# Function to start packet capture using tcpdump
def start_tcpdump_capture():
    tcpdump_command = [
        'tcpdump', '-i', interface, 'host', vulnerable_site_ip,
        '-w', output_file
    ]
    logging.info(f"Starting tcpdump on {interface} with filter 'host {vulnerable_site_ip}'.")

    # Start tcpdump as a subprocess
    tcpdump_process = subprocess.Popen(tcpdump_command)
    return tcpdump_process

# Function to analyze packets in real-time with pyshark
def analyze_live_packets():
    try:
        logging.info(f"Starting live analysis with pyshark on interface {interface} with filter 'host {vulnerable_site_ip}'")
        live_capture = pyshark.LiveCapture(interface=interface, bpf_filter=f"host {vulnerable_site_ip}")

        # Process each packet as it’s captured
        for packet in live_capture.sniff_continuously():
            try:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                protocol = packet.transport_layer
                src_port = packet[protocol].srcport if protocol in packet else 'N/A'
                dst_port = packet[protocol].dstport if protocol in packet else 'N/A'
                logging.info(f"Packet captured: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            except AttributeError:
                # Skip packets without IP or transport layer
                continue
    except Exception as e:
        logging.error(f"Error during live packet analysis with pyshark: {e}")

# Main function to start tcpdump and real-time packet analysis
def start_packet_capture():
    # Start tcpdump capture
    tcpdump_process = start_tcpdump_capture()

    # Run pyshark live analysis in parallel
    analyze_live_packets()

    # Run tcpdump for a specific duration (300 seconds), then stop
    time.sleep(300)
    tcpdump_process.terminate()
    logging.info("tcpdump capture stopped.")

# Schedule packet capture every 5 minutes
schedule.every(5).minutes.do(start_packet_capture)

# Start the scheduler
if __name__ == "__main__":
    start_packet_capture()
    while True:
        schedule.run_pending()
        time.sleep(1)
