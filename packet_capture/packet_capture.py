import subprocess
import logging
import os
import threading
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the interface and IP for vulnerable-site traffic
interface = os.getenv('CAPTURE_INTERFACE', 'eth0')
vulnerable_site_ip = os.getenv('VULNERABLE_SITE_IP', '172.30.0.10')  # Update with actual IP
output_dir = '/persistent/captures'
os.makedirs(output_dir, exist_ok=True)

# Function to start continuous packet capture with rotating files
def start_tshark_capture():
    logging.info(f"Starting continuous tshark on {interface} with filter 'host {vulnerable_site_ip}'.")

    # Command to capture packets with tshark using a ring buffer
    tshark_command = [
    'tshark',
    '-i', interface,                    # Interface to capture on
    '-p',                               # Enable promiscuous mode
    '-f', 'net 172.30.0.0/24',          # Capture all traffic on the subnet
    '-b', 'filesize:10000',             # Rotate files after they reach 10MB
    '-b', 'files:10',                   # Keep the last 10 files
    '-w', os.path.join(output_dir, 'capture')  # Base filename for capture files
    ]


    # Start tshark as a subprocess
    process = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return process

# Function to monitor and log captured packets in real-time
def monitor_captures():
    logging.info("Starting packet monitoring thread.")
    while True:
        # List all capture files
        capture_files = sorted([f for f in os.listdir(output_dir) if f.startswith('capture') and f.endswith('.pcap')])
        if capture_files:
            latest_capture = os.path.join(output_dir, capture_files[-1])
            logging.info(f"Analyzing {latest_capture}")
            # Command to read the latest capture file
            tshark_read_command = [
                'tshark',
                '-r', latest_capture,        # Read from the latest capture file
                '-Y', 'tcp.flags.syn==1 && tcp.flags.ack==0',  # Filter for SYN packets
                '-T', 'fields',              # Output specific fields
                '-e', 'frame.time',          # Timestamp of each frame
                '-e', 'ip.src', '-e', 'ip.dst',  # Source and destination IPs
                '-e', '_ws.col.Protocol',    # Protocol field
                '-e', 'tcp.srcport', '-e', 'tcp.dstport'  # TCP source/destination ports
            ]
            # Execute the command and process the output
            result = subprocess.run(tshark_read_command, capture_output=True, text=True)
            for line in result.stdout.splitlines():
                fields = line.strip().split('\t')
                if len(fields) >= 6:
                    timestamp, src_ip, dst_ip, protocol, src_port, dst_port = fields
                    logging.info(f"Packet captured at {timestamp}: {src_ip}:{src_port} -> {dst_ip}:{dst_port} Protocol: {protocol}")
                else:
                    logging.warning("Incomplete packet information.")
        time.sleep(10)  # Wait before checking for new packets

if __name__ == "__main__":
    # Start the packet capture process
    capture_process = start_tshark_capture()
    # Start the monitoring thread
    monitor_thread = threading.Thread(target=monitor_captures, daemon=True)
    monitor_thread.start()
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping packet capture.")
        capture_process.terminate()
