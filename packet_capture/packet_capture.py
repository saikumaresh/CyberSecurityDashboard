import pyshark
import schedule
import time
import logging
import os
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the interface and filter for vulnerable-site traffic
interface = os.getenv('CAPTURE_INTERFACE', 'eth0')  # Confirm the interface in Docker
# Set vulnerable site address as service name instead of IP
vulnerable_site_ip = os.getenv('VULNERABLE_SITE_IP', 'vulnerable-site')


# Function to start packet capture
def start_packet_capture():
    output_file = f'/persistent/live_capture.pcap'  # Save in persistent volume

    # Apply capture filter to only capture traffic involving vulnerable-site
    capture_filter = f'host {vulnerable_site_ip}'
    capture = pyshark.LiveCapture(interface=interface, output_file=output_file, bpf_filter=capture_filter)
    logging.info(f"Starting packet capture on {interface} for traffic involving {vulnerable_site_ip}. Saving to {output_file}")

    # Capture packets for a specific duration (e.g., 3 minutes)
    capture.sniff(timeout=180)  # 180 seconds = 3 minutes
    logging.info(f"Packet capture completed. File saved as {output_file}")

    # Log details of captured packets
    for packet in capture.sniff_continuously(packet_count=10):  # Limit log output to first 10 packets
        try:
            if 'IP' in packet and 'TCP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                protocol = packet.transport_layer
                src_port = packet[protocol].srcport
                dst_port = packet[protocol].dstport

                logging.info(f"Packet captured: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        except AttributeError:
            # Skip packets that don't have the required attributes
            continue

# Schedule packet capture every 30 minutes
schedule.every(2).minutes.do(start_packet_capture)

# Start the scheduler
if __name__ == "__main__":
    # Run an initial capture on startup to ensure functionality
    start_packet_capture()

    while True:
        schedule.run_pending()
        time.sleep(1)
