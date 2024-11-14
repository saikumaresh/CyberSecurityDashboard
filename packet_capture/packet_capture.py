import pyshark
import schedule
import time
import logging
import os
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the interface and filter for vulnerable-site traffic
interface = os.getenv('CAPTURE_INTERFACE', 'eth0')
# vulnerable_site_ip = os.getenv('VULNERABLE_SITE_IP', 'vulnerable-site')

# Function to start packet capture
def start_packet_capture():
    output_file = f'/persistent/live_capture.pcap'
    # capture_filter = f'host {vulnerable_site_ip}'
    
    try:
        # Apply capture filter to only capture traffic involving vulnerable-site
        # capture = pyshark.LiveCapture(interface=interface, output_file=output_file, bpf_filter=capture_filter)
        capture = pyshark.LiveCapture(interface=interface, output_file=output_file)
        logging.info(f"Starting packet capture on {interface}. Saving to {output_file}")

        # Capture packets for a specific duration (300 seconds)
        capture.sniff(timeout=300)
        logging.info(f"Packet capture completed. File saved as {output_file}")

        # Log details of captured packets
        for packet in capture._packets[:10]:  # Log only the first 10 packets
            try:
                # if 'IP' in packet or 'TCP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                protocol = packet.transport_layer
                src_port = packet[protocol].srcport
                dst_port = packet[protocol].dstport
                logging.info(f"Packet captured: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            except AttributeError:
                continue
    except pyshark.capture.capture.CaptureError as e:
        logging.error(f"Failed to start packet capture: {e}")

# Schedule packet capture every 5 minutes
schedule.every(5).minutes.do(start_packet_capture)

# Start the scheduler
if __name__ == "__main__":
    start_packet_capture()
    while True:
        schedule.run_pending()
        time.sleep(1)
