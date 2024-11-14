import os
import subprocess

def start_packet_capture():
    interface = os.getenv('CAPTURE_INTERFACE', 'eth0')
    target_ip = os.getenv('VULNERABLE_SITE_IP', '172.30.0.10')
    output_dir = '/persistent'

    tshark_command = [
        'tshark',
        '-i', interface,
        '-f', f'host {target_ip}',
        '-b', 'filesize:10000',
        '-b', 'files:10',
        '-w', os.path.join(output_dir, 'live_capture')
    ]

    subprocess.run(tshark_command)

if __name__ == '__main__':
    start_packet_capture()
