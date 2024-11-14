import subprocess
import logging
import os
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the interface and IP for vulnerable-site traffic
interface = os.getenv('CAPTURE_INTERFACE', 'eth0')
vulnerable_site_ip = os.getenv('VULNERABLE_SITE_IP', '172.30.0.10')  # Update with actual IP
output_file = f'/persistent/live_capture.pcap'

# Function to start and stop tshark capture every 2 minutes
def start_timed_tshark_capture():
    while True:
        logging.info(f"Starting tshark on {interface} with filter 'host {vulnerable_site_ip}' for 2 minutes.")

        # Command to capture packets with tshark
        tshark_command = [
            'tshark',
            '-i', interface,                    # Interface to capture on
            '-f', f'host {vulnerable_site_ip}',  # Capture filter for target IP
            '-w', output_file,                  # Output file to save the capture
            '-a', 'duration:120'                # Stop capture after 120 seconds (2 minutes)
        ]

        # Start tshark as a subprocess and capture packets
        with subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
            try:
                # Process output and wait for tshark to complete the 2-minute capture
                for line in process.stdout:
                    logging.info(line.strip())  # Log tshark output if needed
                process.wait()
                logging.info("tshark capture completed for this interval.")
            except Exception as e:
                logging.error(f"Error during packet capture with tshark: {e}")
            finally:
                process.terminate()  # Ensure process is terminated

        # Wait for a few seconds before restarting the capture
        time.sleep(1)  # Add a short delay if needed before restarting the capture

if __name__ == "__main__":
    start_timed_tshark_capture()
